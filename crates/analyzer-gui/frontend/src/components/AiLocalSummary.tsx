export function AiLocalSummary({ text }: { text: string }) {
  return (
    <details className="local-ai-summary">
      <summary>本地结果整理 · 部分完成</summary>
      <p>
        仅整理成功回复，不代表完成新的 AI
        关联推理。完整内容仍保留在发现列表和运行历史中。
      </p>
      <pre>{text}</pre>
    </details>
  );
}
