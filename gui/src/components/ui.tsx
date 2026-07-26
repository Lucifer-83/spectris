/* Reusable presentational primitives for the toolkit UI. */
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import { IconAlert, IconCheck, IconExternal, IconInfo, IconKey, IconX } from "./icons";
import type { AttackInfo } from "../attackInfo";

/* ---------- Card ---------- */
export function Card({
  title,
  subtitle,
  icon,
  right,
  children,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  icon?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="card">
      {(title || right) && (
        <header className="card__head">
          {icon}
          <div style={{ flex: 1, minWidth: 0 }}>
            {title && <h3>{title}</h3>}
            {subtitle && <div className="card__sub">{subtitle}</div>}
          </div>
          {right}
        </header>
      )}
      <div className="card__body">{children}</div>
    </section>
  );
}

/* ---------- Button ---------- */
type Variant = "default" | "primary" | "danger" | "ghost";
export function Button({
  variant = "default",
  small,
  icon,
  children,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; small?: boolean; icon?: ReactNode }) {
  const cls = [
    "btn",
    variant !== "default" && `btn--${variant}`,
    small && "btn--sm",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button className={cls} {...rest}>
      {icon}
      {children}
    </button>
  );
}

/* ---------- Pill ---------- */
export function Pill({
  variant = "neutral",
  live,
  dot = true,
  children,
}: {
  variant?: "neutral" | "ok" | "warn" | "danger" | "accent" | "info";
  live?: boolean;
  dot?: boolean;
  children: ReactNode;
}) {
  const cls = ["pill", variant !== "neutral" && `pill--${variant}`, live && "pill--live"]
    .filter(Boolean)
    .join(" ");
  return (
    <span className={cls}>
      {dot && <span className="dot" />}
      {children}
    </span>
  );
}

/* ---------- Field + Input ---------- */
export function Field({
  label,
  hint,
  children,
}: {
  label: ReactNode;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <label className="field">
      <span className="field__label">{label}</span>
      {children}
      {hint && <span className="field__hint">{hint}</span>}
    </label>
  );
}

export function Input({
  mono,
  className = "",
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }) {
  return <input className={["input", mono && "input--mono", className].filter(Boolean).join(" ")} {...rest} />;
}

/* ---------- Banner ---------- */
export function Banner({
  variant,
  children,
}: {
  variant: "error" | "warn" | "info" | "ok";
  children: ReactNode;
}) {
  const Icon = variant === "error" ? IconX : variant === "warn" ? IconAlert : variant === "ok" ? IconCheck : IconInfo;
  return (
    <div className={`banner banner--${variant}`}>
      <Icon size={16} />
      <div>{children}</div>
    </div>
  );
}

/* ---------- Recovered password ----------
   One consistent, prominent GREEN display used at the top of EVERY attack module
   (Crack, WPS, Auto, Evil Twin) so a recovered password always shows in the same
   place and the same way — green because green = success (the app accent is blue). */
export function PasswordHit({
  password,
  target,
  label = "Password recovered",
}: {
  password: string;
  target?: string;
  label?: string;
}) {
  return (
    <div className="pw-hit">
      <span className="pw-hit__label">
        <IconKey size={15} /> {label}
        {target ? <span className="pw-hit__target"> · {target}</span> : null}
      </span>
      <span className="pw-hit__value" title="Recovered Wi-Fi password">{password}</span>
    </div>
  );
}

/* ---------- Empty state ---------- */
export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

/* ---------- Success meter ---------- */
function successTone(v: number): string {
  if (v >= 65) return "ok";
  if (v >= 40) return "accent";
  if (v >= 25) return "warn";
  return "danger";
}

export function SuccessMeter({ value, label = "Typical success", caveat }: { value: number; label?: string; caveat?: string }) {
  const tone = successTone(value);
  return (
    <div className="meter" title={caveat}>
      <span className="meter__label">{label}</span>
      <span className={`meter__track meter--${tone}`}>
        <span className="meter__fill" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
      </span>
      <span className="meter__pct mono">{value}%</span>
    </div>
  );
}

/* ---------- Attack meta header ----------
   The banner atop every view: what the step does, a "read more" link, its
   typical success rate, and — where relevant — which tool is recommended. */
export function AttackMeta({ info }: { info: AttackInfo }) {
  return (
    <div className="attack-meta glass">
      <div className="attack-meta__main">
        <p className="attack-meta__tagline">{info.tagline}</p>
        <a className="attack-meta__doc" href={info.doc} target="_blank" rel="noreferrer">
          Read more about this attack <IconExternal size={13} />
        </a>
      </div>

      {(info.success != null || info.tools) && (
        <div className="attack-meta__side">
          {info.success != null && <SuccessMeter value={info.success} caveat={info.caveat} />}
          {info.tools && (
            <div className="tool-chips">
              {info.tools.map((t) => (
                <span key={t.name} className={`tool-chip ${t.recommended ? "tool-chip--rec" : ""}`} title={t.note}>
                  {t.recommended && <span className="tool-chip__star">★</span>}
                  <span className="tool-chip__name">{t.name}</span>
                  <span className="tool-chip__pct mono">{t.success}%</span>
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
