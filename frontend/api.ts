import { useNavigate } from "react-router";
import { useEffect, useRef, useState } from "react";

const SLIDES = [
  {
    id: 0,
    image:
      "https://images.unsplash.com/photo-1489436969537-cf0c1dc69cba?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxuZXR3b3JrJTIwc2VjdXJpdHklMjBkYXJrJTIwYWJzdHJhY3QlMjBpbmZyYXN0cnVjdHVyZSUyMGdsb3dpbmd8ZW58MXx8fHwxNzc0MTI2OTg5fDA&ixlib=rb-4.1.0&q=80&w=1080",
    title: "Your Digital Safety\nStarts Here",
    body: "Cervais gives you military-grade protection for your identity, devices, and communications â€” in the palm of your hand.",
  },
  {
    id: 1,
    image:
      "https://images.unsplash.com/photo-1648415383716-f9828037d2a3?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxjeWJlciUyMHNlY3VyaXR5JTIwcGFkbG9jayUyMGVuY3J5cHRlZCUyMGRhdGElMjBwcm90ZWN0aW9uJTIwZGFyayUyMGJsdWV8ZW58MXx8fHwxNzc0MTI2OTk2fDA&ixlib=rb-4.1.0&q=80&w=1080",
    title: "Zero-Trust.\nEnd-to-End.",
    body: "Every packet, every session, every handshake â€” verified and encrypted. No implicit trust. No backdoors.",
  },
  {
    id: 2,
    image:
      "https://images.unsplash.com/photo-1762417108293-91614140073a?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=M3w3Nzg4Nzd8MHwxfHNlYXJjaHwxfHxkZWNlbnRyYWxpemVkJTIwaWRlbnRpdHklMjBibG9ja2NoYWluJTIwY3J5cHRvZ3JhcGh5JTIwYWJzdHJhY3QlMjBkYXJrfGVufDF8fHx8MTc3NDEyNjk5NHww&ixlib=rb-4.1.0&q=80&w=1080",
    title: "Your Identity,\nYour Control",
    body: "Decentralised identifiers (DIDs) put you in charge. No central authority. No single point of failure.",
  },
];

const AUTO_ADVANCE_MS = 3500;

export function OB01Welcome() {
  const navigate = useNavigate();
  const [active, setActive] = useState(0);
  const [showSwipeHint, setShowSwipeHint] = useState(true);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const hintTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Touch / drag state
  const touchStartX = useRef<number | null>(null);

  const startTimer = () => {
    if (timerRef.current) clearInterval(timerRef.current);
    timerRef.current = setInterval(() => {
      setActive((prev) => (prev + 1) % SLIDES.length);
    }, AUTO_ADVANCE_MS);
  };

  useEffect(() => {
    startTimer();
    // Hide swipe hint after 2.5s
    hintTimerRef.current = setTimeout(() => setShowSwipeHint(false), 2500);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      if (hintTimerRef.current) clearTimeout(hintTimerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const goTo = (idx: number) => {
    setActive(idx);
    startTimer();
    setShowSwipeHint(false);
  };

  const handleTouchStart = (e: React.TouchEvent) => {
    touchStartX.current = e.touches[0].clientX;
  };

  const handleTouchEnd = (e: React.TouchEvent) => {
    if (touchStartX.current === null) return;
    const delta = e.changedTouches[0].clientX - touchStartX.current;
    if (Math.abs(delta) > 40) {
      const next =
        delta < 0
          ? (active + 1) % SLIDES.length
          : (active - 1 + SLIDES.length) % SLIDES.length;
      goTo(next);
    }
    touchStartX.current = null;
  };

  const slide = SLIDES[active];

  return (
    <div
      className="relative flex flex-col overflow-hidden"
      style={{ height: "100dvh", backgroundColor: "var(--background)" }}
      onTouchStart={handleTouchStart}
      onTouchEnd={handleTouchEnd}
    >
      {/* â”€â”€ IMAGE PANEL â”€â”€ */}
      <div className="relative overflow-hidden" style={{ flex: "0 0 56%" }}>
        {SLIDES.map((s, i) => (
          <img
            key={s.id}
            src={s.image}
            alt=""
            className="absolute inset-0 w-full h-full object-cover"
            style={{
              opacity: i === active ? 1 : 0,
              transition: "opacity 0.7s ease",
              willChange: "opacity",
            }}
          />
        ))}

        {/* dark gradient at bottom of image */}
        <div
          className="absolute bottom-0 left-0 right-0"
          style={{
            height: "50%",
            background:
              "linear-gradient(to bottom, transparent, var(--background))",
          }}
        />
        {/* top scrim */}
        <div
          className="absolute top-0 left-0 right-0"
          style={{
            height: "30%",
            background:
              "linear-gradient(to bottom, rgba(0,0,0,0.45), transparent)",
          }}
        />

        {/* Swipe hint â€” fades out after 2.5s */}
        <div
          className="absolute bottom-8 left-0 right-0 flex items-center justify-center gap-2 pointer-events-none"
          style={{
            opacity: showSwipeHint ? 1 : 0,
            transition: "opacity 0.6s ease",
          }}
        >
          <div
            style={{ width: "18px", height: "1px", backgroundColor: "rgba(255,255,255,0.4)" }}
          />
          <span
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "11px",
              color: "rgba(255,255,255,0.55)",
              letterSpacing: "0.06em",
            }}
          >
            swipe to explore
          </span>
          <div
            style={{ width: "18px", height: "1px", backgroundColor: "rgba(255,255,255,0.4)" }}
          />
        </div>
      </div>

      {/* â”€â”€ CONTENT PANEL â”€â”€ */}
      <div
        className="relative flex flex-col flex-1"
        style={{ backgroundColor: "var(--background)", zIndex: 10 }}
      >
        {/* Text */}
        <div className="flex flex-col px-7 pt-2 flex-1">
          <h2
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "28px",
              fontWeight: 700,
              lineHeight: 1.2,
              color: "var(--foreground)",
              letterSpacing: "-0.02em",
              marginBottom: "10px",
              whiteSpace: "pre-line",
              minHeight: "68px",
            }}
          >
            {slide.title}
          </h2>
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
              fontWeight: "var(--font-weight-normal)",
              color: "var(--muted-foreground)",
              lineHeight: 1.6,
              minHeight: "60px",
            }}
          >
            {slide.body}
          </p>
        </div>

        {/* Dot indicators */}
        <div className="flex items-center justify-center gap-2 py-4">
          {SLIDES.map((_, i) => (
            <button
              key={i}
              onClick={() => goTo(i)}
              style={{
                height: "6px",
                width: i === active ? "18px" : "6px",
                borderRadius: "9999px",
                backgroundColor:
                  i === active ? "var(--primary)" : "var(--border)",
                border: "none",
                padding: 0,
                cursor: "pointer",
                transition: "width 0.3s ease, background-color 0.3s ease",
              }}
            />
          ))}
        </div>

        {/* CTAs */}
        <div className="flex flex-col items-center gap-2 px-6 pb-10">
          <button
            onClick={() => navigate("/signup")}
            className="w-full flex items-center justify-center active:opacity-80"
            style={{
              height: "52px",
              backgroundColor: "var(--primary)",
              color: "var(--primary-foreground)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-base)",
              fontWeight: "var(--font-weight-semibold)",
              borderRadius: "var(--radius)",
              boxShadow:
                "0 0 28px color-mix(in srgb, var(--primary) 30%, transparent)",
              border: "none",
              cursor: "pointer",
              transition: "opacity 0.15s ease",
            }}
          >
            Create Account
          </button>

          <div
            className="flex items-center justify-center gap-1"
            style={{ height: "44px" }}
          >
            <span
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-normal)",
                color: "var(--muted-foreground)",
              }}
            >
              Already have an account?
            </span>
            <button
              onClick={() => navigate("/login")}
              className="active:opacity-60"
              style={{
                background: "none",
                border: "none",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: "var(--font-weight-semibold)",
                color: "var(--primary)",
                cursor: "pointer",
                padding: "0 2px",
              }}
            >
              Login
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}