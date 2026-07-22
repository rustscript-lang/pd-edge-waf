// Standalone JIT segfault reproducer for rustscript master.
// Captures SIGSEGV and dumps the Rust backtrace before re-raising.
// Does NOT modify rustscript -- installs signal handlers and uses std::backtrace.

use std::backtrace::Backtrace;
use std::sync::atomic::{AtomicUsize, Ordering};

use vm::{JitConfig, Vm, VmStatus};

static REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

fn compile_program() -> vm::CompiledProgram {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ruleset = std::fs::read_to_string(root.join("rules/ruleset_bundle.rss"))
        .expect("ruleset bundle should be readable");
    let source = format!(
        r#"{ruleset}
assert((&inspect_request(new_state(
    "GET",
    "/products",
    "category=books&page=2",
    "HTTP/1.1",
    "192.0.2.10",
    {{
        "host": "shop.example.test",
        "accept": "text/html,application/xhtml+xml",
        "user-agent": "pd-edge-waf-perf/1.0"
    }},
    {{ "category": "books", "page": "2" }},
    ""
)))["blocked"] == "0");
"allow";
"#
    );
    let compiled = vm::compile_source(&source).expect("ruleset should compile");
    assert!(
        compiled.program.local_count <= 256,
        "perf program must fit the standard VM local-slot format"
    );
    assert!(compiled.program.imports.is_empty());
    compiled
}

#[test]
#[ignore = "segfault reproducer; run with --ignored --nocapture"]
fn jit_master_segfault_at_max_trace_len_256() {
    install_signal_handlers();

    let compiled = compile_program();
    let program = compiled.program;
    let mut vm = Vm::new_with_jit_config(
        program.clone(),
        JitConfig {
            enabled: true,
            hot_loop_threshold: 8,
            max_trace_len: 256,
        },
    );
    vm.set_jit_native_bridge_stats_enabled(true);

    for req_idx in 0..32usize {
        let prev = REQUEST_COUNT.fetch_add(1, Ordering::SeqCst);
        println!(
            "jit_segfault_repro: starting request #{}, total={}",
            req_idx,
            prev + 1
        );

        let status = vm.run();
        match status {
            Ok(VmStatus::Halted) => {
                println!("jit_segfault_repro: request #{} halted", req_idx);
            }
            Ok(other) => {
                println!(
                    "jit_segfault_repro: request #{} ended with {:?}",
                    req_idx, other
                );
            }
            Err(err) => {
                println!(
                    "jit_segfault_repro: request #{} errored: {:?}",
                    req_idx, err
                );
            }
        }
        vm.reset_for_reuse();
    }

    panic!("jit_segfault_repro: did not segfault after 32 requests");
}

extern "C" fn sigsegv_handler(
    sig: libc::c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut libc::ucontext_t,
) {
    let req = REQUEST_COUNT.load(Ordering::SeqCst);
    let bt = Backtrace::force_capture();
    eprintln!("============================================================");
    eprintln!(
        "JIT_SEGFAULT_REPRO: caught signal {} at request #{}",
        sig, req
    );
    eprintln!("JIT_SEGFAULT_REPRO: backtrace follows");
    eprintln!("{}", bt);
    eprintln!("============================================================");
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
    let _ = info;
}

fn install_signal_handlers() {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = sigsegv_handler as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_SIGINFO | libc::SA_RESETHAND;
        libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGABRT, &action, std::ptr::null_mut());
    }
}
