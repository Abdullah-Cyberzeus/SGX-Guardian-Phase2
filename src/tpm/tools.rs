use super::{TpmConfig, TpmError};
use std::fs;
use std::process::{Command, Stdio};

pub struct Tpm2Cli {
    cfg: TpmConfig,
}

impl Tpm2Cli {
    pub fn new(cfg: TpmConfig) -> Self {
        Self { cfg }
    }

    pub fn available(&self) -> bool {
        self.run_str("tpm2_getcap", &["properties-fixed"], None)
            .is_ok()
    }

    pub fn handle_exists(&self, handle: u32) -> bool {
        let handle_text = format!("0x{:08x}", handle);
        self.persistent_handles_text()
            .map(|text| text.to_lowercase().contains(&handle_text))
            .unwrap_or(false)
    }

    pub fn readpublic_der(&self, handle: u32, out_path: &str) -> Result<(), TpmError> {
        if let Some(parent) = std::path::Path::new(out_path).parent() {
            fs::create_dir_all(parent)?;
        }

        let handle_text = format!("0x{:08X}", handle);
        self.run_strings(
            "tpm2_readpublic",
            &[
                "-c".to_string(),
                handle_text,
                "-f".to_string(),
                "der".to_string(),
                "-o".to_string(),
                out_path.to_string(),
            ],
            None,
        )?;
        Ok(())
    }

    pub fn create_ek(&self, handle: u32) -> Result<(), TpmError> {
        let handle_text = format!("0x{:08X}", handle);
        self.run_candidates(
            "tpm2_createek",
            &[
                vec![
                    "-c".to_string(),
                    handle_text.clone(),
                    "-G".to_string(),
                    "ecc".to_string(),
                ],
                vec![
                    "-c".to_string(),
                    handle_text,
                    "-G".to_string(),
                    "ecc256".to_string(),
                ],
            ],
            None,
        )?;
        Ok(())
    }

    pub fn provision_persistent_signing_key(
        &self,
        handle: u32,
        out_pub_path: &str,
        attributes: &str,
        owner_auth: Option<&str>,
        key_auth: Option<&str>,
    ) -> Result<(), TpmError> {
        let dir = tempfile::tempdir()?;
        let primary_ctx = dir.path().join("primary.ctx");
        let key_pub = dir.path().join("key.pub");
        let key_priv = dir.path().join("key.priv");
        let key_ctx = dir.path().join("key.ctx");

        let primary_ctx_str = primary_ctx.to_string_lossy().to_string();
        let key_pub_str = key_pub.to_string_lossy().to_string();
        let key_priv_str = key_priv.to_string_lossy().to_string();
        let key_ctx_str = key_ctx.to_string_lossy().to_string();
        let handle_text = format!("0x{:08X}", handle);

        self.create_primary(&primary_ctx_str, owner_auth)?;
        self.run_candidates(
            "tpm2_create",
            &[
                self.create_args(
                    &primary_ctx_str,
                    &key_pub_str,
                    &key_priv_str,
                    attributes,
                    "ecc256",
                    key_auth,
                ),
                self.create_args(
                    &primary_ctx_str,
                    &key_pub_str,
                    &key_priv_str,
                    attributes,
                    "ecc:nist_p256",
                    key_auth,
                ),
            ],
            None,
        )?;
        self.run_strings(
            "tpm2_load",
            &[
                "-C".to_string(),
                primary_ctx_str.clone(),
                "-u".to_string(),
                key_pub_str.clone(),
                "-r".to_string(),
                key_priv_str.clone(),
                "-c".to_string(),
                key_ctx_str.clone(),
            ],
            None,
        )?;

        let mut evict_args = vec![
            "-C".to_string(),
            "o".to_string(),
            "-c".to_string(),
            key_ctx_str,
            handle_text,
        ];
        if let Some(auth) = owner_auth {
            evict_args.push("-P".to_string());
            evict_args.push(auth.to_string());
        }
        self.run_strings("tpm2_evictcontrol", &evict_args, None)?;
        self.readpublic_der(handle, out_pub_path)?;
        Ok(())
    }

    pub fn evict_handle(&self, handle: u32, owner_auth: Option<&str>) -> Result<(), TpmError> {
        let handle_text = format!("0x{:08X}", handle);
        let mut args = vec![
            "-C".to_string(),
            "o".to_string(),
            "-c".to_string(),
            handle_text,
        ];
        if let Some(auth) = owner_auth {
            args.push("-P".to_string());
            args.push(auth.to_string());
        }
        self.run_strings("tpm2_evictcontrol", &args, None)?;
        Ok(())
    }

    pub fn sign_plain(
        &self,
        handle: u32,
        input_path: &str,
        sig_path: &str,
        key_auth: Option<&str>,
    ) -> Result<(), TpmError> {
        let handle_text = format!("0x{:08X}", handle);
        let mut candidates = vec![
            vec![
                "-c".to_string(),
                handle_text.clone(),
                "-g".to_string(),
                "sha256".to_string(),
                "-s".to_string(),
                "ecdsa".to_string(),
                "-f".to_string(),
                "plain".to_string(),
                "-o".to_string(),
                sig_path.to_string(),
                "-m".to_string(),
                input_path.to_string(),
            ],
            vec![
                "-c".to_string(),
                handle_text.clone(),
                "-g".to_string(),
                "sha256".to_string(),
                "-s".to_string(),
                "ecdsa".to_string(),
                "-f".to_string(),
                "plain".to_string(),
                "-o".to_string(),
                sig_path.to_string(),
                input_path.to_string(),
            ],
            vec![
                "-c".to_string(),
                handle_text,
                "--message".to_string(),
                input_path.to_string(),
                "-g".to_string(),
                "sha256".to_string(),
                "-s".to_string(),
                "ecdsa".to_string(),
                "-f".to_string(),
                "plain".to_string(),
                "-o".to_string(),
                sig_path.to_string(),
            ],
        ];
        if let Some(auth) = key_auth {
            for args in candidates.iter_mut() {
                args.push("-p".to_string());
                args.push(auth.to_string());
            }
        }
        self.run_candidates("tpm2_sign", &candidates, None)?;
        Ok(())
    }

    pub fn pcr_read_text(&self, selection: &str) -> Result<String, TpmError> {
        let bytes = self.run_str("tpm2_pcrread", &[selection], None)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    fn create_primary(&self, ctx_path: &str, owner_auth: Option<&str>) -> Result<(), TpmError> {
        let mut first = vec![
            "-C".to_string(),
            "o".to_string(),
            "-g".to_string(),
            "sha256".to_string(),
            "-G".to_string(),
            "ecc256".to_string(),
            "-c".to_string(),
            ctx_path.to_string(),
        ];
        if let Some(auth) = owner_auth {
            first.push("-P".to_string());
            first.push(auth.to_string());
        }

        let mut second = vec![
            "-C".to_string(),
            "o".to_string(),
            "-g".to_string(),
            "sha256".to_string(),
            "-G".to_string(),
            "ecc:nist_p256".to_string(),
            "-c".to_string(),
            ctx_path.to_string(),
        ];
        if let Some(auth) = owner_auth {
            second.push("-P".to_string());
            second.push(auth.to_string());
        }

        self.run_candidates("tpm2_createprimary", &[first, second], None)?;
        Ok(())
    }

    fn create_args(
        &self,
        primary_ctx: &str,
        key_pub: &str,
        key_priv: &str,
        attributes: &str,
        curve: &str,
        key_auth: Option<&str>,
    ) -> Vec<String> {
        let mut args = vec![
            "-C".to_string(),
            primary_ctx.to_string(),
            "-g".to_string(),
            "sha256".to_string(),
            "-G".to_string(),
            curve.to_string(),
            "-u".to_string(),
            key_pub.to_string(),
            "-r".to_string(),
            key_priv.to_string(),
            "-a".to_string(),
            attributes.to_string(),
        ];
        if let Some(auth) = key_auth {
            args.push("-p".to_string());
            args.push(auth.to_string());
        }
        args
    }

    fn persistent_handles_text(&self) -> Result<String, TpmError> {
        let bytes = self.run_str("tpm2_getcap", &["handles-persistent"], None)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    fn run_candidates(
        &self,
        tool: &str,
        candidates: &[Vec<String>],
        stdin: Option<&[u8]>,
    ) -> Result<Vec<u8>, TpmError> {
        let mut last_error = None;

        for args in candidates {
            match self.run_strings(tool, args, stdin) {
                Ok(output) => return Ok(output),
                Err(error) => last_error = Some(error),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            TpmError::Tool(
                tool.to_string(),
                "no runnable argument candidates".to_string(),
            )
        }))
    }

    fn run_str(
        &self,
        tool: &str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<Vec<u8>, TpmError> {
        let args = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        self.run_strings(tool, &args, stdin)
    }

    fn run_strings(
        &self,
        tool: &str,
        args: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<Vec<u8>, TpmError> {
        use std::io::Write;

        let mut cmd = Command::new(tool);
        cmd.env("TPM2TOOLS_TCTI", &self.cfg.tcti);
        cmd.args(args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        }

        let mut child = cmd
            .spawn()
            .map_err(|error| TpmError::Tool(tool.to_string(), error.to_string()))?;

        if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
            pipe.write_all(data)
                .map_err(|error| TpmError::Tool(tool.to_string(), error.to_string()))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|error| TpmError::Tool(tool.to_string(), error.to_string()))?;

        if output.status.success() {
            return Ok(output.stdout);
        }

        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if stderr.is_empty() {
            stdout
        } else if stdout.is_empty() {
            stderr
        } else {
            format!("{} | {}", stderr, stdout)
        };

        Err(TpmError::Tool(tool.to_string(), detail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    struct PathGuard(Option<std::ffi::OsString>);

    impl Drop for PathGuard {
        fn drop(&mut self) {
            match self.0.take() {
                Some(path) => std::env::set_var("PATH", path),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    #[cfg(unix)]
    fn install_tool(dir: &Path, name: &str, body: &str) {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write fake TPM tool");
        let mut permissions = std::fs::metadata(&path)
            .expect("tool metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).expect("make fake TPM tool executable");
    }

    fn use_tool_dir(dir: &Path) -> PathGuard {
        let previous = std::env::var_os("PATH");
        std::env::set_var("PATH", dir);
        PathGuard(previous)
    }

    fn cfg() -> super::TpmConfig {
        super::TpmConfig {
            device: "/dev/tpm0".into(),
            tcti: "tabrmd:bus_name=com.example.tpm".into(),
            explicit_backend: false,
            dik_handle: 0x81020000,
            dkp_handle_base: 0x81010000,
            ek_handle: 0x81010001,
            pcr_selection: "0:0,1,2".into(),
            owner_auth: None,
            key_auth: None,
        }
    }

    #[test]
    fn create_args_includes_auth_when_provided() {
        let t = Tpm2Cli::new(cfg());
        let args = t.create_args(
            "/tmp/ctx",
            "/tmp/pub",
            "/tmp/priv",
            "attr",
            "ecc256",
            Some("p@ss"),
        );
        assert!(args.contains(&"-p".to_string()));
        assert_eq!(args.last().map(String::as_str), Some("p@ss"));
        assert!(args.iter().any(|s| s == "attr"));
        assert!(args.iter().any(|s| s == "ecc256"));
    }

    #[test]
    fn create_args_without_auth_has_no_p_flag() {
        let t = Tpm2Cli::new(cfg());
        let args = t.create_args("/tmp/ctx", "/tmp/pub", "/tmp/priv", "attrs", "ecc", None);
        assert!(!args.contains(&"-p".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn availability_handles_success_failure_and_missing_tools() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("tool directory");
        install_tool(
            dir.path(),
            "tpm2_getcap",
            "[ \"$TPM2TOOLS_TCTI\" = \"tabrmd:bus_name=com.example.tpm\" ]",
        );
        let _path = use_tool_dir(dir.path());
        assert!(Tpm2Cli::new(cfg()).available());

        install_tool(dir.path(), "tpm2_getcap", "echo probe-failed >&2; exit 7");
        assert!(!Tpm2Cli::new(cfg()).available());
        std::fs::remove_file(dir.path().join("tpm2_getcap")).expect("remove fake tool");
        assert!(!Tpm2Cli::new(cfg()).available());
    }

    #[cfg(unix)]
    #[test]
    fn persistent_handle_matching_is_case_insensitive_and_failure_safe() {
        let _lock = crate::test_support::blocking_env_lock();
        let dir = tempfile::tempdir().expect("tool directory");
        install_tool(
            dir.path(),
            "tpm2_getcap",
            "printf '%s\\n' '- 0X81020000' '- 0x81020001'",
        );
        let _path = use_tool_dir(dir.path());
        let cli = Tpm2Cli::new(cfg());
        assert!(cli.handle_exists(0x8102_0000));
        assert!(cli.handle_exists(0x8102_0001));
        assert!(!cli.handle_exists(0x8102_0002));

        install_tool(dir.path(), "tpm2_getcap", "exit 1");
        assert!(!cli.handle_exists(0x8102_0000));
    }

    #[cfg(unix)]
    #[test]
    fn readpublic_creates_parent_and_passes_uppercase_handle() {
        let _lock = crate::test_support::blocking_env_lock();
        let tools = tempfile::tempdir().expect("tool directory");
        install_tool(
            tools.path(),
            "tpm2_readpublic",
            "[ \"$1\" = '-c' ] && [ \"$2\" = '0x8102ABCD' ] && [ \"$3\" = '-f' ] && [ \"$4\" = 'der' ] && [ \"$5\" = '-o' ] || exit 8\nprintf DER > \"$6\"",
        );
        let _path = use_tool_dir(tools.path());
        let output = tempfile::tempdir()
            .expect("output root")
            .path()
            .join("nested/public.der");

        Tpm2Cli::new(cfg())
            .readpublic_der(0x8102_abcd, output.to_str().expect("UTF-8 path"))
            .expect("read public key");
        assert_eq!(std::fs::read(output).expect("public key"), b"DER");
    }

    #[cfg(unix)]
    #[test]
    fn candidate_commands_fall_back_and_empty_candidates_report_tool_error() {
        let _lock = crate::test_support::blocking_env_lock();
        let tools = tempfile::tempdir().expect("tool directory");
        install_tool(
            tools.path(),
            "tpm2_createek",
            "case \"$*\" in *ecc:nist_p256*|*ecc256*) exit 0;; *) exit 4;; esac",
        );
        let _path = use_tool_dir(tools.path());
        let cli = Tpm2Cli::new(cfg());
        cli.create_ek(0x8101_0001).expect("candidate succeeds");

        let error = cli
            .run_candidates("never-run", &[], None)
            .expect_err("empty candidate list must fail");
        assert!(
            matches!(error, TpmError::Tool(tool, detail) if tool == "never-run" && detail.contains("no runnable"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn command_error_combines_stderr_and_stdout_and_pcr_output_round_trips() {
        let _lock = crate::test_support::blocking_env_lock();
        let tools = tempfile::tempdir().expect("tool directory");
        install_tool(
            tools.path(),
            "failing-tool",
            "printf stdout-detail; printf stderr-detail >&2; exit 3",
        );
        install_tool(
            tools.path(),
            "tpm2_pcrread",
            "[ \"$1\" = 'sha256:0,2' ] || exit 9\nprintf '  0: 0xabc\\n'",
        );
        let _path = use_tool_dir(tools.path());
        let cli = Tpm2Cli::new(cfg());
        let error = cli
            .run_strings("failing-tool", &[], None)
            .expect_err("command must fail");
        assert!(
            matches!(error, TpmError::Tool(_, detail) if detail == "stderr-detail | stdout-detail")
        );
        assert_eq!(
            cli.pcr_read_text("sha256:0,2").expect("PCR output"),
            "  0: 0xabc\n"
        );
    }
}
