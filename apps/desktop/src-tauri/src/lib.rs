//! Termoso desktop: Tauri 2 shell. Rust owns state, storage, transport and
//! sessions; the webview only renders and forwards user input.

mod account;
mod agent_server;
mod ai;
mod automations;
mod avatars;
mod backup;
mod cli;
mod cloud;
mod cloud_sync;
mod commands;
mod commands_tools;
mod complete;
mod edits;
mod error;
mod forwarding;
mod import;
#[cfg(target_os = "linux")]
mod linux_graphics;
mod logs;
mod mosh;
mod multiplayer;
mod presence;
mod prompts;
mod quick;
mod rotation;
mod security;
mod sessions;
mod sftp;
mod smoke;
mod snippets;
mod sshid;
mod state;
mod sync;
mod tailnet;
mod team;
mod theme_import;
mod trust;
mod update;
mod webdav;
mod workspaces;
mod zmodem;

use termoso_client::{hosts, keychain};

use tauri::Manager;

use crate::state::AppState;
use crate::update::UpdateHub;

pub fn run() {
    if let Some(exit) = cli::early_exit(std::env::args().skip(1)) {
        // Release builds have no console of their own on Windows: borrow the parent's.
        #[cfg(windows)]
        let _ = unsafe {
            windows::Win32::System::Console::AttachConsole(
                windows::Win32::System::Console::ATTACH_PARENT_PROCESS,
            )
        };
        match exit {
            cli::EarlyExit::Stdout(text) => println!("{text}"),
            cli::EarlyExit::Stderr(text) => {
                eprintln!("{text}");
                std::process::exit(2);
            }
        }
        return;
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("TERMOSO_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    #[cfg(target_os = "linux")]
    linux_graphics::apply_workarounds();

    let mut context = tauri::generate_context!();
    // WebKitGTK strips file:// URIs from HTML5 drops, so OS drops need the
    // native handler there; WebView2 needs it off for HTML5 drag-and-drop.
    for window in &mut context.config_mut().app.windows {
        window.drag_drop_enabled = cfg!(not(windows));
    }

    tauri::Builder::default()
        // First, so a second launch (e.g. the OS opening an ssh:// link) hands
        // its arguments to the running instance instead of starting another.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            quick::forward_files(app, &args);
            quick::forward_links(app, &args);
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
                let _ = w.unminimize();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let state = AppState::open().map_err(|e| {
                tracing::error!(error = %e, "cannot open profile");
                std::io::Error::other(e.to_string())
            })?;
            tracing::info!(
                profile = %state.profile_dir.display(),
                master = ?state.master_source(),
                locked = state.is_locked(),
                "profile opened"
            );
            let locked = state.is_locked();
            app.manage(state);
            app.manage(UpdateHub::default());
            app.manage(quick::LaunchFiles::from_args(std::env::args().skip(1)));
            app.manage(quick::LaunchLinks::from_args(std::env::args().skip(1)));
            #[cfg(target_os = "macos")]
            if let Err(e) = quick::install_app_menu(app) {
                tracing::debug!(error = %e, "app menu not installed");
            }
            #[cfg(windows)]
            std::thread::spawn(quick::install_jump_list);
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async {
                // Hardware-backed device keys are not implemented on desktop yet: say so.
                let posture = termoso_core::posture::collect(Some(false)).await;
                tracing::debug!(?posture, "device posture");
                termoso_core::posture::set_reported(posture);
            });
            tauri::async_runtime::spawn(security::inactivity_watcher(handle.clone()));
            tauri::async_runtime::spawn(automations::executor(handle.clone()));
            if !locked {
                tauri::async_runtime::spawn(startup(handle));
            }
            Ok(())
        })
        .on_page_load(smoke::on_page_load)
        .invoke_handler(tauri::generate_handler![
            smoke::smoke_report,
            commands::app_info,
            commands::app_quit,
            commands::deep_links_register,
            commands::launch_files,
            commands::launch_links,
            commands::zmodem_receive,
            commands::zmodem_send,
            commands::zmodem_cancel,
            commands::settings_get,
            commands::settings_set,
            security::vault_status,
            security::vault_unlock,
            security::vault_lock,
            security::vault_activity,
            security::master_password_set,
            security::master_password_remove,
            commands::vaults_list,
            commands::vault_default,
            commands::entities_list,
            commands::entity_get,
            commands::entity_save,
            commands::entity_delete,
            commands::entity_move,
            commands::hosts_list,
            commands::host_form,
            commands::host_save,
            commands::webdav_pem_file,
            commands::webdav_client_identity_inspect,
            commands::host_delete,
            commands::hosts_delete,
            commands::host_duplicate,
            commands::hosts_move,
            commands::serial_ports,
            commands::local_shells,
            commands::hosts_copy_to_vault,
            commands::host_inherited,
            commands::groups_list,
            commands::group_save,
            commands::group_form,
            commands::group_save_form,
            commands::group_duplicate,
            commands::group_delete,
            commands::tags_list,
            commands::tag_update,
            commands::tag_delete,
            commands::tags_merge,
            commands::history_connections,
            commands::history_commands,
            commands::history_record_command,
            commands::history_delete,
            commands::history_clear_commands,
            commands::history_clear_connections,
            complete::terminal_list_dir,
            complete::terminal_insert_password,
            complete::terminal_host_identity,
            workspaces::workspaces_get,
            workspaces::workspaces_set,
            commands::sessions_list,
            commands::terminal_open,
            commands::terminal_attach,
            commands::terminal_write,
            commands::terminal_resize,
            commands::terminal_close,
            commands::prompt_answer,
            commands::sftp_sessions_list,
            commands::sftp_open,
            commands::sftp_close,
            commands::sftp_list,
            commands::sftp_stat,
            commands::sftp_mkdir,
            commands::sftp_rename,
            commands::sftp_remove,
            commands::sftp_chmod,
            commands::sftp_copy,
            commands::local_home,
            commands::local_list,
            commands::local_drives,
            commands::local_stat,
            commands::local_mkdir,
            commands::local_rename,
            commands::local_remove,
            commands::local_open,
            commands::transfer_probe,
            commands::transfer_start,
            commands::transfer_cancel,
            commands::transfer_pause,
            commands::transfer_resume,
            commands::transfer_forget,
            commands::drop_begin,
            commands::drop_write,
            commands::drop_mkdir,
            commands::drop_abort,
            commands::edits_list,
            commands::syncs_list,
            commands::sync_start,
            commands::sftp_diff,
            commands::sync_stop,
            commands::edit_open,
            commands::edit_upload_now,
            commands::edit_close,
            commands_tools::keys_list,
            agent_server::agent_server_status,
            agent_server::agent_server_refresh,
            commands_tools::key_generate,
            commands_tools::key_import,
            commands_tools::fido2_devices,
            commands_tools::fido2_generate,
            commands_tools::fido2_load_resident,
            commands_tools::key_import_file,
            commands_tools::key_import_agent,
            commands_tools::key_import_agent_file,
            commands_tools::key_inspect,
            commands_tools::key_inspect_file,
            commands_tools::certificate_inspect,
            commands_tools::certificate_inspect_file,
            commands_tools::key_certificate,
            commands_tools::key_set_certificate,
            commands_tools::key_set_certificate_file,
            commands_tools::key_copy_to_vault,
            commands_tools::key_rename,
            commands_tools::key_change_passphrase,
            commands_tools::key_remember_passphrase,
            commands_tools::key_public,
            commands_tools::key_export,
            commands_tools::key_export_file,
            commands_tools::key_export_to_host,
            commands_tools::agent_keys,
            commands_tools::key_delete,
            commands_tools::identities_list,
            commands_tools::identity_save,
            commands_tools::identity_delete,
            commands_tools::identity_copy_to_vault,
            commands_tools::master_key_migrate,
            commands_tools::pf_rules,
            commands_tools::pf_save,
            commands_tools::pf_runtimes,
            commands_tools::pf_start,
            commands_tools::pf_stop,
            commands_tools::pf_delete,
            commands_tools::pf_duplicate,
            commands_tools::pf_copy_to_vault,
            commands_tools::snippets_list,
            commands_tools::snippet_save,
            commands_tools::snippet_delete,
            commands_tools::snippet_set_targets,
            commands_tools::snippet_run,
            commands_tools::snippet_run_quiet,
            commands_tools::snippet_packages,
            commands_tools::snippet_package_save,
            commands_tools::snippet_package_delete,
            commands_tools::snippet_package_copy_to_vault,
            commands_tools::snippet_copy_to_vault,
            commands_tools::known_hosts_list,
            commands_tools::known_host_forget,
            commands_tools::known_host_forget_host,
            commands_tools::host_key_pins,
            commands_tools::host_key_pin,
            commands_tools::host_key_unpin,
            commands_tools::known_hosts_import_text,
            commands_tools::known_hosts_import_file,
            commands_tools::known_hosts_export_text,
            commands_tools::known_hosts_export_file,
            commands_tools::known_hosts_default_path,
            commands_tools::import_scan_ssh,
            commands_tools::import_parse_file,
            commands_tools::import_scan_putty_registry,
            commands_tools::import_scan_securecrt_dir,
            commands_tools::theme_import_file,
            commands_tools::import_ssh_dir_default,
            commands_tools::import_csv_template,
            commands_tools::import_csv_template_save,
            commands_tools::import_apply,
            commands_tools::import_discard,
            commands_tools::cloud_discover,
            commands_tools::cloud_import,
            commands_tools::cloud_discard,
            commands_tools::cloud_sync_list,
            commands_tools::cloud_sync_get,
            commands_tools::cloud_sync_save,
            commands_tools::cloud_sync_forget,
            commands_tools::cloud_sync_run,
            commands_tools::mdns_browse,
            commands_tools::tailnet_scan,
            commands_tools::hosts_export_csv,
            commands_tools::hosts_export_as,
            commands_tools::wake_host,
            commands_tools::gateways_list,
            commands_tools::backup_export,
            commands_tools::backup_inspect,
            commands_tools::backup_discard,
            commands_tools::backup_restore,
            commands_tools::logs_list,
            commands_tools::log_read,
            commands_tools::log_export,
            commands_tools::log_annotate,
            commands_tools::vault_session_logging_set,
            commands_tools::log_delete,
            commands_tools::log_bookmarks,
            commands_tools::log_bookmark_add,
            commands_tools::log_bookmark_delete,
            commands_tools::account_status,
            commands_tools::account_server_info,
            commands_tools::account_login,
            commands_tools::account_mfa,
            commands_tools::account_mfa_email_send,
            commands_tools::account_webauthn_challenge,
            commands_tools::account_reauth_start,
            commands_tools::account_reauth_mfa,
            commands_tools::account_reauth_email_code,
            commands_tools::account_reauth_mfa_email_send,
            commands_tools::account_reauth_webauthn_challenge,
            commands_tools::account_reauth_cancel,
            commands_tools::account_device_approve,
            commands_tools::account_device_resend,
            commands_tools::account_cancel_login,
            commands_tools::account_sso_start,
            commands_tools::account_sso_discover,
            commands_tools::save_text_file,
            commands_tools::account_sso_poll,
            commands_tools::account_sso_callback,
            commands_tools::account_sso_cancel,
            commands_tools::account_register,
            commands_tools::account_sign_out,
            commands_tools::account_sync_now,
            commands_tools::account_set_credential_sync,
            commands_tools::account_devices,
            commands_tools::account_device_revoke,
            commands_tools::account_vault_members,
            commands_tools::teams_list,
            commands_tools::team_create,
            commands_tools::team_rename,
            commands_tools::team_set_security,
            commands_tools::team_delete,
            commands_tools::team_leave,
            commands_tools::team_accept_invite,
            commands_tools::team_members,
            commands_tools::team_member_set_role,
            commands_tools::team_member_remove,
            commands_tools::team_member_delete_account,
            commands_tools::team_invites,
            commands_tools::team_invite,
            commands_tools::team_invite_revoke,
            commands_tools::team_pending_keys,
            commands_tools::team_audit,
            commands_tools::team_permissions,
            commands_tools::team_roles,
            commands_tools::team_role_create,
            commands_tools::team_role_update,
            commands_tools::team_role_delete,
            commands_tools::team_set_default_role,
            commands_tools::team_role_mappings,
            commands_tools::team_set_role_mappings,
            commands_tools::team_policies,
            commands_tools::team_update_policies,
            commands_tools::team_ca,
            commands_tools::team_update_ca,
            commands_tools::team_delete_ca,
            commands_tools::team_rotate_ca,
            commands_tools::team_ca_certificates,
            commands_tools::team_ca_revoke,
            commands_tools::team_ca_local,
            commands_tools::team_access_reviews,
            commands_tools::team_access_review,
            commands_tools::team_access_review_open,
            commands_tools::team_access_review_decide,
            commands_tools::team_access_review_complete,
            commands_tools::team_access_review_cancel,
            commands_tools::team_break_glass,
            commands_tools::team_break_glass_configure,
            commands_tools::team_break_glass_delete,
            commands_tools::team_break_glass_use,
            commands_tools::team_break_glass_end,
            commands_tools::team_audit_verify,
            commands_tools::team_automations,
            commands_tools::team_automation_create,
            commands_tools::team_automation_update,
            commands_tools::team_automation_delete,
            commands_tools::team_automation_run_now,
            commands_tools::team_automation_runs,
            commands_tools::team_automations_execute,
            commands_tools::team_idp,
            commands_tools::team_update_idp,
            commands_tools::team_test_idp,
            commands_tools::team_delete_idp,
            commands_tools::team_acl,
            commands_tools::team_upsert_acl,
            commands_tools::team_delete_acl,
            commands_tools::acl_me,
            commands_tools::team_logs,
            commands_tools::team_logs_export,
            commands_tools::team_rotation,
            commands_tools::team_create_rotation_jobs,
            commands_tools::rotation_jobs,
            commands_tools::rotation_update_job,
            commands_tools::rotation_cancel_job,
            commands_tools::rotation_run_job,
            commands_tools::rotation_mark_done,
            commands_tools::team_access_requests,
            commands_tools::team_create_access_request,
            commands_tools::team_cancel_access_request,
            commands_tools::team_decide_access_request,
            commands_tools::team_data,
            commands_tools::team_export,
            commands_tools::team_schedule_deletion,
            commands_tools::team_cancel_deletion,
            commands_tools::team_devices,
            commands_tools::team_approve_device,
            commands_tools::team_reject_device,
            commands_tools::team_webhooks,
            commands_tools::team_webhook_create,
            commands_tools::team_webhook_update,
            commands_tools::team_webhook_delete,
            commands_tools::team_webhook_test,
            commands_tools::team_webhook_deliveries,
            commands_tools::team_presence,
            commands_tools::account_profile,
            commands_tools::user_avatar,
            commands_tools::account_set_presence_hidden,
            commands_tools::ai_status,
            commands_tools::ai_set_enabled,
            commands_tools::ai_ask,
            commands_tools::team_vault_create,
            commands_tools::team_vault_rename,
            commands_tools::team_vault_delete,
            commands_tools::team_vault_set_access,
            commands_tools::team_vault_remove_access,
            commands_tools::team_vault_rotate_key,
            commands_tools::sshid_view,
            commands_tools::sshid_create,
            commands_tools::sshid_delete,
            commands_tools::sshid_publish,
            commands_tools::sshid_rotate,
            commands_tools::sshid_add_fido2,
            commands_tools::sshid_add_public_key,
            commands_tools::sshid_remove_key,
            commands_tools::sshid_remove_device,
            commands_tools::multiplayer_start,
            commands_tools::multiplayer_stop,
            commands_tools::multiplayer_info,
            commands_tools::multiplayer_set_control,
            commands_tools::update_check,
            commands_tools::update_install,
            commands_tools::update_restart,
        ])
        .build(context)
        .expect("error while building Termoso")
        .run(|app, event| match event {
            tauri::RunEvent::Exit => app.state::<AppState>().edits.close_all(),
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Opened { urls } => quick::forward_urls(app, &urls),
            _ => {}
        });
}

/// Background work once the vault is open (at start-up, or after every
/// unlock): restore the account session, sweep old recordings and bring up
/// auto-start forwards.
pub(crate) async fn startup(app: tauri::AppHandle) {
    let state = app.state::<AppState>();
    let Ok(store) = state.store() else {
        return;
    };
    let settings = state.settings().unwrap_or_default();
    edits::sweep_stale();
    match logs::prune(&store, settings.log_retention_days) {
        Ok(n) if n > 0 => tracing::info!(pruned = n, "old recordings removed"),
        Ok(_) => {}
        Err(e) => tracing::warn!("log retention sweep failed: {e}"),
    }
    drop(store);
    match account::resume(&app).await {
        Ok(Some(a)) => tracing::info!(email = %a.email, "account session restored"),
        Ok(None) => {}
        Err(e) => tracing::warn!("account resume failed: {e}"),
    }
    if settings.serve_ssh_agent {
        match agent_server::reconcile(&app).await {
            Ok(s) => tracing::info!(keys = s.keys.len(), "ssh-agent serving vault keys"),
            Err(e) => tracing::warn!("ssh-agent start failed: {e}"),
        }
    }
    if settings.autostart_forwarding {
        match forwarding::autostart(&app).await {
            Ok(ids) if !ids.is_empty() => {
                tracing::info!(count = ids.len(), "forwarding rules auto-started")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!("forwarding autostart failed: {e}"),
        }
    }
    if state
        .lock
        .first_startup_done
        .swap(true, std::sync::atomic::Ordering::SeqCst)
    {
        return;
    }
    if settings.update_check == "startup" {
        update::check_on_startup(&app).await;
    }
    tauri::async_runtime::spawn(cloud_sync::scheduler(app));
}
