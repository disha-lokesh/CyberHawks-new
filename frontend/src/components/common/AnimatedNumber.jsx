import { useEffect, useRef, useState } from "react";

/** Lightweight count-up: no external dep, animates from previous value to `value`. */
export default function AnimatedNumber({ value = 0, decimals = 0, duration = 500, className = "" }) {
  const [display, setDisplay] = useState(value);
  const prevRef = useRef(value);
  const frameRef = useRef();

  useEffect(() => {
    const from = prevRef.current;
    const to = value;
    const start = performance.now();

    function tick(now) {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setDisplay(from + (to - from) * eased);
      if (t < 1) frameRef.current = requestAnimationFrame(tick);
      else prevRef.current = to;
    }
    frameRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frameRef.current);
  }, [value, duration]);

  return <span className={className}>{display.toFixed(decimals)}</span>;
}
