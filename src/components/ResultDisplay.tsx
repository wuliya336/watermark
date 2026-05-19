import { Button } from "@heroui/react";

interface ImageResult {
  type: "image";
  dataUrl: string;
  durationMs: number;
  filename: string;
}

interface TextResult {
  type: "text";
  text: string;
  durationMs: number;
}

type ResultData = ImageResult | TextResult;

interface ResultDisplayProps {
  result: ResultData | null;
  onDownload?: () => void;
}

function formatDuration(ms: number): string {
  if (ms >= 1000) {
    return `${(ms / 1000).toFixed(2)}s`;
  }
  return `${Math.round(ms)}ms`;
}

function renderWatermarkText(text: string): string {
  const jsonStart = text.indexOf("{");
  const jsonEnd = text.lastIndexOf("}");
  if (jsonStart === -1 || jsonEnd === -1 || jsonEnd < jsonStart) {
    return text;
  }
  const jsonText = text.slice(jsonStart, jsonEnd + 1);
  try {
    const value = JSON.parse(jsonText);
    const timestamp = value.a ?? 0;
    const pluginVersion = value.b ?? "未知";
    const account = String(value.c ?? "未知");
    const formattedDate = timestamp
      ? new Date(timestamp).toLocaleString("zh-CN")
      : "未知";
    return `【原始水印】\n${text}\n\n【解析结果】\n  时间戳：${formattedDate}\n  详细信息：${pluginVersion}\n  账号：${account}`;
  } catch {
    return text;
  }
}

export default function ResultDisplay({ result, onDownload }: ResultDisplayProps) {
  if (!result) return null;

  return (
    <div className="flex h-full flex-col gap-2 overflow-hidden">
      {result.type === "image" ? (
        <>
          <div
            className="min-h-0 flex-1 overflow-hidden rounded-lg"
            style={{ border: "1px solid var(--border)" }}
          >
            <img
              src={result.dataUrl}
              alt="处理结果"
              className="h-full w-full object-contain"
              draggable={false}
            />
          </div>
          <div className="flex shrink-0 items-center justify-between gap-2">
            <Button
              variant="primary"
              size="sm"
              onPress={onDownload}
              className="shrink-0"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="mr-1">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="7 10 12 15 17 10" />
                <line x1="12" y1="15" x2="12" y2="3" />
              </svg>
              下载图片
            </Button>
            <span className="text-[10px] font-mono-nums" style={{ color: "var(--muted-secondary)" }}>
              耗时 {formatDuration(result.durationMs)}
            </span>
          </div>
        </>
      ) : (
        <div className="flex h-full flex-col overflow-hidden">
          <div
            className="min-h-0 flex-1 overflow-auto rounded-lg p-3"
            style={{
              background: "var(--surface-secondary)",
              border: "1px solid var(--border)",
            }}
          >
            <pre
              className="whitespace-pre-wrap font-mono text-xs leading-relaxed"
              style={{ color: "var(--foreground)" }}
            >
              {renderWatermarkText(result.text)}
            </pre>
          </div>
          <div className="mt-2 flex shrink-0 items-center justify-between">
            <span className="text-[10px] font-mono-nums" style={{ color: "var(--muted-secondary)" }}>
              耗时 {formatDuration(result.durationMs)}
            </span>
            <button
              className="text-[10px] transition-micro hover:opacity-80"
              style={{ color: "var(--muted)" }}
              onClick={() => navigator.clipboard.writeText(result.text)}
            >
              复制内容
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
