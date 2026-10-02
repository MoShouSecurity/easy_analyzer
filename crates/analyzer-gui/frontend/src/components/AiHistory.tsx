import { useState, useRef } from "react";
import {
  History,
  ChevronDown,
  CheckCircle2,
  AlertCircle,
  LoaderCircle,
} from "lucide-react";
import { api } from "../lib/api";
import { number } from "../lib/utils";
import { Button } from "./ui/button";
import { AiLocalSummary } from "./AiLocalSummary";
import type { RunSummary, AiBatch, Page } from "../types";
export function AiHistory({
  runs,
  sessionId,
  onOffset,
  onError,
  initiallyOpen = false,
}: {
  initiallyOpen?: boolean;
  runs: Page<RunSummary> | undefined;
  sessionId: number;
  onOffset: (v: number) => void;
  onError: (s: string) => void;
}) {
  const [open, setOpen] = useState(initiallyOpen),
    [expanded, setExpanded] = useState<number | null>(null),
    [batches, setBatches] = useState<Page<AiBatch> | null>(null),
    [loading, setLoading] = useState(false);
  const revision = useRef(0);
  async function load(run: number, offset = 0) {
    const current = ++revision.current;
    setExpanded(run);
    setBatches(null);
    setLoading(true);
    try {
      const page = await api.batches(sessionId, run, offset);
      if (current === revision.current) setBatches(page);
    } catch (e) {
      if (current === revision.current) onError(String(e));
    } finally {
      if (current === revision.current) setLoading(false);
    }
  }
  return (
    <div className="history-panel">
      <button className="history-toggle" onClick={() => setOpen(!open)}>
        <History size={14} />
        <span>运行历史</span>
        <span className="small-badge">{runs?.total || 0}</span>
        {runs?.items[0] && (
          <small>
            最近一次：{runs.items[0].completed}/{runs.items[0].batches} 批 ·{" "}
            {number(runs.items[0].analyzed)} 条
          </small>
        )}
        <ChevronDown size={13} className={open ? "rotated" : ""} />
      </button>
      {open && (
        <div className="history-scroll">
          {runs?.items.map((run) => (
            <div key={run.index} className="run-item">
              <button
                onClick={() =>
                  expanded === run.index ? setExpanded(null) : load(run.index)
                }
              >
                {run.completed === run.batches ? (
                  <CheckCircle2 size={14} className="success" />
                ) : (
                  <AlertCircle size={14} className="warning" />
                )}
                <strong>#{run.index + 1}</strong>
                <span>{run.model}</span>
                <small>
                  已分析 {number(run.analyzed)}/{number(run.selected)} 条 ·{" "}
                  {run.completed}/{run.batches} 批
                </small>
                <ChevronDown size={12} />
              </button>
              {expanded === run.index && (
                <div className="batch-list">
                  {run.local_summary && (
                    <AiLocalSummary text={run.local_summary} />
                  )}
                  {loading ? (
                    <LoaderCircle className="spin" size={15} />
                  ) : (
                    batches?.items.map((batch) => (
                      <details key={batch.index}>
                        <summary>
                          批次 {batch.index} · {batch.evidence_ids.length} 条 ·{" "}
                          {batch.attempts.length} 次回复
                          {batch.error && (
                            <span className="warning"> 未完成</span>
                          )}
                        </summary>
                        {batch.error && (
                          <p className="warning">{batch.error}</p>
                        )}
                        {batch.attempts.map((a, i) => (
                          <details className="raw-reply" key={i}>
                            <summary>原始回复 {i + 1}</summary>
                            {a.error && <p className="warning">{a.error}</p>}
                            <pre>{a.response || "没有回复内容"}</pre>
                          </details>
                        ))}
                      </details>
                    ))
                  )}
                  {batches && (
                    <div className="history-pager">
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={batches.offset === 0}
                        onClick={() =>
                          load(run.index, Math.max(0, batches.offset - 10))
                        }
                      >
                        上一组批次
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={batches.offset + 10 >= batches.total}
                        onClick={() => load(run.index, batches.offset + 10)}
                      >
                        下一组批次
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
          {!runs?.items.length && <p className="muted">尚未运行 AI 分析。</p>}
          {runs && runs.total > 20 && (
            <div className="history-pager">
              <Button
                variant="ghost"
                size="sm"
                disabled={!runs.offset}
                onClick={() => onOffset(Math.max(0, runs.offset - 20))}
              >
                上一组运行
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={runs.offset + 20 >= runs.total}
                onClick={() => onOffset(runs.offset + 20)}
              >
                下一组运行
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
