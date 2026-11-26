//! Send one payload over three simulated paths using the `paranoid` policy.
//!
//! Run with: `cargo run --example basic`

use pathguard::sim::World;
use pathguard::Policy;

fn main() {
    let world = World::new();
    let sender = world.sender(Policy::paranoid());
    let mut paths = vec![
        world.honest_path("fiber", &["isp-a", "ix-1", "dst"], 1),
        world.honest_path("lte", &["carrier-b", "ix-2", "dst"], 2),
        world.honest_path("sat", &["sat-c", "ix-3", "dst"], 3),
    ];
    match sender.send(b"hello from PathGuard", &mut paths) {
        Ok(report) => {
            println!("{}", report.render());
            println!("receiver got: {:?}", String::from_utf8_lossy(&world.take_delivered()[0]));
        }
        Err(e) => {
            eprintln!("not delivered: {e}");
            if let Some(r) = e.report() {
                eprintln!("{}", r.render());
            }
        }
    }
}
