export function Defs() {
  return (
    <defs>
      {[
        { id: "haloAlpha", c: "#14B8A6" },
        { id: "haloBravo", c: "#9333EA" },
        { id: "haloCharlie", c: "#F59E0B" },
        { id: "haloDelta", c: "#3B82F6" },
      ].map((g) => (
        <radialGradient key={g.id} id={g.id} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor={g.c} stopOpacity=".55" />
          <stop offset="60%" stopColor={g.c} stopOpacity=".08" />
          <stop offset="100%" stopColor={g.c} stopOpacity="0" />
        </radialGradient>
      ))}
      {[
        { id: "overlapAB", c: "#a7f3d0" },
        { id: "overlapBC", c: "#fde68a" },
        { id: "overlapCD", c: "#bae6fd" },
      ].map((g) => (
        <radialGradient key={g.id} id={g.id} cx="50%" cy="50%" r="50%">
          <stop offset="0%" stopColor={g.c} stopOpacity=".40" />
          <stop offset="60%" stopColor={g.c} stopOpacity=".06" />
          <stop offset="100%" stopColor={g.c} stopOpacity="0" />
        </radialGradient>
      ))}
      <filter id="topoCyberGlow" x="-100%" y="-100%" width="300%" height="300%">
        <feGaussianBlur stdDeviation="3.2" result="blur" />
        <feMerge>
          <feMergeNode in="blur" />
          <feMergeNode in="SourceGraphic" />
        </feMerge>
      </filter>
      <linearGradient id="topoNodeGlass" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stopColor="#172334" />
        <stop offset="52%" stopColor="#09111c" />
        <stop offset="100%" stopColor="#03070d" />
      </linearGradient>
    </defs>
  );
}
