import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";

const NODE_STYLE = {
  APK: { shape: "hexagon", color: "#e94560" },
  IPAddress: { shape: "circle", color: "#00d4ff" },
  Domain: { shape: "rect", color: "#f39c12" },
  Certificate: { shape: "diamond", color: "#9b59b6" },
  PhoneNumber: { shape: "circle", color: "#00ff88" },
  JARMHash: { shape: "triangle", color: "#e67e22" },
};

function styleFor(labels) {
  for (const l of labels || []) if (NODE_STYLE[l]) return NODE_STYLE[l];
  return { shape: "circle", color: "#6b6b8a" };
}

function shapePath(shape, r) {
  switch (shape) {
    case "hexagon": {
      const pts = d3.range(6).map((i) => {
        const a = (Math.PI / 3) * i - Math.PI / 2;
        return [r * Math.cos(a), r * Math.sin(a)];
      });
      return d3.line()(pts) + "Z";
    }
    case "diamond":
      return `M0,${-r} L${r},0 L0,${r} L${-r},0 Z`;
    case "triangle":
      return `M0,${-r} L${r * 0.87},${r * 0.5} L${-r * 0.87},${r * 0.5} Z`;
    case "rect":
      return `M${-r},${-r * 0.7} h${r * 2} v${r * 1.4} h${-r * 2} Z`;
    default:
      return null; // circle handled separately
  }
}

export default function ForceGraph({ nodes, edges, onNodeClick }) {
  const svgRef = useRef(null);
  const [dims, setDims] = useState({ w: 800, h: 600 });

  useEffect(() => {
    const handle = () => {
      const el = svgRef.current?.parentElement;
      if (el) setDims({ w: el.clientWidth, h: el.clientHeight });
    };
    handle();
    window.addEventListener("resize", handle);
    return () => window.removeEventListener("resize", handle);
  }, []);

  useEffect(() => {
    if (!svgRef.current) return;
    const { w, h } = dims;
    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();

    const zoomLayer = svg.append("g");
    svg.call(
      d3.zoom().on("zoom", (event) => zoomLayer.attr("transform", event.transform))
    );

    const nodeData = nodes.map((n) => ({ ...n }));
    const linkData = edges
      .map((e) => ({ ...e, source: e.source, target: e.target }))
      .filter((e) => nodeData.some((n) => n.id === e.source) && nodeData.some((n) => n.id === e.target));

    const sim = d3
      .forceSimulation(nodeData)
      .force("link", d3.forceLink(linkData).id((d) => d.id).distance(90))
      .force("charge", d3.forceManyBody().strength(-220))
      .force("center", d3.forceCenter(w / 2, h / 2))
      .force("collide", d3.forceCollide(28));

    const link = zoomLayer
      .append("g")
      .selectAll("line")
      .data(linkData)
      .join("line")
      .attr("stroke", "#1a1a2e")
      .attr("stroke-width", 1.2);

    const node = zoomLayer
      .append("g")
      .selectAll("g")
      .data(nodeData)
      .join("g")
      .style("cursor", "pointer")
      .call(
        d3
          .drag()
          .on("start", (event, d) => {
            if (!event.active) sim.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on("drag", (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on("end", (event, d) => {
            if (!event.active) sim.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on("click", (event, d) => onNodeClick?.(d))
      .on("mouseenter", (event, d) => {
        const connected = new Set([d.id]);
        linkData.forEach((l) => {
          if (l.source.id === d.id) connected.add(l.target.id);
          if (l.target.id === d.id) connected.add(l.source.id);
        });
        node.style("opacity", (n) => (connected.has(n.id) ? 1 : 0.15));
        link.style("opacity", (l) => (l.source.id === d.id || l.target.id === d.id ? 1 : 0.05));
      })
      .on("mouseleave", () => {
        node.style("opacity", 1);
        link.style("opacity", 1);
      })
      .on("dblclick", (event, d) => {
        const scale = 2.2;
        svg
          .transition()
          .duration(500)
          .call(
            d3.zoom().transform,
            d3.zoomIdentity.translate(w / 2, h / 2).scale(scale).translate(-d.x, -d.y)
          );
      });

    node.each(function (d) {
      const g = d3.select(this);
      const style = styleFor(d.labels);
      const r = 14;
      if (style.shape === "circle") {
        g.append("circle").attr("r", r).attr("fill", style.color).attr("fill-opacity", 0.85);
      } else {
        g.append("path").attr("d", shapePath(style.shape, r)).attr("fill", style.color).attr("fill-opacity", 0.85);
      }
      g.append("text")
        .text(d.properties?.value || d.properties?.package_name || d.labels?.[0] || "")
        .attr("y", r + 12)
        .attr("text-anchor", "middle")
        .attr("font-size", 9)
        .attr("font-family", "monospace")
        .attr("fill", "#6b6b8a");
    });

    sim.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);
      node.attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    return () => sim.stop();
  }, [nodes, edges, dims]);

  return <svg ref={svgRef} width="100%" height="100%" className="bg-bg" />;
}

export { NODE_STYLE };
