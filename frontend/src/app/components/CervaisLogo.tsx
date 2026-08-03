import logoSrc from "@/assets/sgx-guardian-logo.png";

interface CervaisLogoProps {
  /** Controls the rendered width in px; height scales automatically. */
  width?: number;
  /** Legacy alias – treated as width so existing call-sites don't break. */
  size?: number;
  className?: string;
}

export function CervaisLogo({ width, size, className }: CervaisLogoProps) {
  const w = width ?? size ?? 120;
  return (
    <img
      src={logoSrc}
      alt="SG-X Guardian"
      width={w}
      style={{ width: w, height: "auto", display: "block" }}
      className={className}
      draggable={false}
    />
  );
}
