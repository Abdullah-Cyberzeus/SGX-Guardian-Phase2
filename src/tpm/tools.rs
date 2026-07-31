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
