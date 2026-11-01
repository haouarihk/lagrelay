//! Terminal dashboard shown while connected.
use crate::session::Live;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Sparkline, Table};
use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub fn fmt_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let (mut v, mut i) = (b as f64, 0);
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

pub fn fmt_rate(bytes_per_sec: f64) -> String {
    let bits = bytes_per_sec * 8.0;
    if bits >= 1e6 {
        format!("{:.1} Mbit/s", bits / 1e6)
    } else {
        format!("{:.0} kbit/s", bits / 1e3)
    }
}

pub fn fmt_uptime(s: u64) -> String {
    format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60)
}

fn ms(v: Option<f64>) -> String {
    v.map_or("-".to_string(), |x| format!("{x:.0} ms"))
}

pub fn route_name(direct: bool) -> &'static str {
    if direct {
        "direct"
    } else {
        "relay"
    }
}

pub fn server_cells(v: &crate::session::ServerView) -> [String; 5] {
    [v.ip.to_string(), route_name(v.live_direct).into(), ms(v.direct_ms), ms(v.relay_ms), route_name(v.prefer_direct).into()]
}

struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = std::io::stdout().execute(LeaveAlternateScreen);
    }
}

/// Runs the dashboard until the user quits. Blocking; call via spawn_blocking.
pub fn dashboard(live: &Live) -> Result<()> {
    enable_raw_mode()?;
    std::io::stdout().execute(EnterAlternateScreen)?;
    let _restore = Restore;
    let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
    let mut hist: VecDeque<u64> = VecDeque::with_capacity(240);
    let (mut last_up, mut last_down, mut last_t) = (0u64, 0u64, Instant::now());
    let (mut rate_up, mut rate_down) = (0.0f64, 0.0f64);
    let mut tick = Instant::now();
    loop {
        if tick.elapsed() >= Duration::from_millis(500) {
            tick = Instant::now();
            let s = live.snapshot.lock().unwrap().clone();
            if hist.len() == 240 {
                hist.pop_front();
            }
            hist.push_back(s.best_rtt_ms.map_or(0, |r| r.round() as u64));
            let dt = last_t.elapsed().as_secs_f64().max(0.001);
            rate_up = s.bytes_up.saturating_sub(last_up) as f64 / dt;
            rate_down = s.bytes_down.saturating_sub(last_down) as f64 / dt;
            (last_up, last_down, last_t) = (s.bytes_up, s.bytes_down, Instant::now());
        }
        let s = live.snapshot.lock().unwrap().clone();
        let status = live.status.lock().unwrap().clone();
        let want = live.want_routes.load(Ordering::Relaxed);
        term.draw(|f| {
            let areas = Layout::vertical([Constraint::Length(5), Constraint::Min(5), Constraint::Length(6), Constraint::Length(6), Constraint::Length(1)]).split(f.area());
            let color = if status == "connected" { Color::Green } else { Color::Yellow };
            let rtt = s.best_rtt_ms.map_or("--".to_string(), |r| format!("{r:.0} ms"));
            let head = vec![
                Line::from(vec![
                    Span::styled(format!(" {status} "), Style::default().fg(Color::Black).bg(color)),
                    Span::raw(format!("  {}  via exit {}  ({})", live.game, s.exit, live.capture_desc)),
                ]),
                Line::from(format!(" ping {rtt}   up {}   down {}   uptime {}", fmt_rate(rate_up), fmt_rate(rate_down), fmt_uptime(live.started.elapsed().as_secs()))),
                Line::from(format!(
                    " sent {}   received {}   lost-packet recoveries {}   unrecovered {}   route switches {}",
                    fmt_bytes(s.bytes_up),
                    fmt_bytes(s.bytes_down),
                    s.recovered,
                    s.lost,
                    s.switches
                )),
            ];
            f.render_widget(Paragraph::new(head).block(Block::default().title(" LagRelay ").borders(Borders::ALL)), areas[0]);
            let rows: Vec<Row> = s
                .paths
                .iter()
                .map(|p| {
                    let (state, st) = match (p.active, p.alive) {
                        (true, true) => ("ACTIVE", Style::default().fg(Color::Green)),
                        (true, false) => ("FAILING", Style::default().fg(Color::Red)),
                        (false, true) => ("standby", Style::default().fg(Color::DarkGray)),
                        (false, false) => ("down", Style::default().fg(Color::Red)),
                    };
                    Row::new(vec![
                        Cell::from(state).style(st),
                        Cell::from(p.label.clone()),
                        Cell::from(if p.alive { format!("{:.0}", p.rtt_ms) } else { "-".into() }),
                        Cell::from(if p.alive { format!("{:.1}", p.jitter_ms) } else { "-".into() }),
                        Cell::from(format!("{:.0}%", p.loss_pct)),
                    ])
                })
                .collect();
            let table = Table::new(rows, [Constraint::Length(8), Constraint::Min(20), Constraint::Length(7), Constraint::Length(8), Constraint::Length(6)])
                .header(Row::new(["state", "route", "ping", "jitter", "loss"]).style(Style::default().add_modifier(Modifier::BOLD)))
                .block(Block::default().title(format!(" Routes: {want} carrying traffic ")).borders(Borders::ALL));
            f.render_widget(table, areas[1]);
            let width = areas[2].width.saturating_sub(2) as usize;
            let data: Vec<u64> = hist.iter().rev().take(width).rev().copied().collect();
            f.render_widget(
                Sparkline::default().data(&data).style(Style::default().fg(Color::Cyan)).block(Block::default().title(" Ping history ").borders(Borders::ALL)),
                areas[2],
            );
            let servers = live.servers.lock().unwrap().clone();
            let rows: Vec<Row> = servers.iter().map(|v| Row::new(crate::ui::server_cells(v))).collect();
            let table = Table::new(rows, [Constraint::Length(17), Constraint::Length(9), Constraint::Length(9), Constraint::Length(9), Constraint::Min(10)])
                .header(Row::new(["server", "using", "direct", "relay", "new connections"]).style(Style::default().add_modifier(Modifier::BOLD)))
                .block(Block::default().title(" Game servers: direct or relay ").borders(Borders::ALL));
            f.render_widget(table, areas[3]);
            f.render_widget(Paragraph::new(" q quit   + more routes   - fewer routes").style(Style::default().fg(Color::DarkGray)), areas[4]);
        })?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Press {
                    continue;
                }
                match k.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),
                    KeyCode::Char('+') | KeyCode::Char('=') => {
                        let v = live.want_routes.load(Ordering::Relaxed);
                        live.want_routes.store((v + 1).min(crate::engine::MAX_PATHS as u32), Ordering::Relaxed);
                    }
                    KeyCode::Char('-') => {
                        let v = live.want_routes.load(Ordering::Relaxed);
                        live.want_routes.store(v.saturating_sub(1).max(1), Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(2048), "2.0 KB");
        assert_eq!(fmt_bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(fmt_rate(125_000.0), "1.0 Mbit/s");
        assert_eq!(fmt_rate(1000.0), "8 kbit/s");
        assert_eq!(fmt_uptime(3661), "01:01:01");
    }
}
