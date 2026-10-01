import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";
import {
  ChevronLeft,
  ChevronRight,
  Database,
  LoaderCircle,
} from "lucide-react";
import { Button } from "./ui/button";
import { Select } from "./ui/select";
import { number } from "../lib/utils";
import type { Page } from "../types";
export function DataTable<T>({
  page,
  columns,
  id,
  selected,
  onSelect,
  loading = false,
  empty = "当前筛选没有结果",
  onPage,
  onSize,
  limit = 100,
}: {
  page: Page<T> | null;
  columns: ColumnDef<T>[];
  id: (v: T) => string;
  selected?: string | null;
  onSelect?: (v: T) => void;
  loading?: boolean;
  empty?: string;
  onPage?: (offset: number) => void;
  onSize?: (limit: number) => void;
  limit?: number;
}) {
  const table = useReactTable({
    data: page?.items || [],
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: id,
    manualPagination: true,
    rowCount: page?.total || 0,
  });
  return (
    <div className="data-table">
      <div className="table-scroll">
        <table>
          <colgroup>
            {table.getAllLeafColumns().map((c) => (
              <col
                key={c.id}
                style={
                  c.columnDef.size ? { width: c.columnDef.size } : undefined
                }
              />
            ))}
          </colgroup>
          <thead>
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((h) => (
                  <th key={h.id}>
                    {flexRender(h.column.columnDef.header, h.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map((row) => (
              <tr
                key={row.id}
                tabIndex={onSelect ? 0 : undefined}
                onClick={() => onSelect?.(row.original)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") onSelect?.(row.original);
                }}
                className={selected === row.id ? "selected" : ""}
              >
                {row.getVisibleCells().map((c) => (
                  <td key={c.id}>
                    {flexRender(c.column.columnDef.cell, c.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {!table.getRowModel().rows.length && (
          <div className="table-empty">
            {loading ? (
              <LoaderCircle className="spin" size={23} />
            ) : (
              <Database size={24} strokeWidth={1.3} />
            )}
            <span>{loading ? "正在读取证据" : empty}</span>
          </div>
        )}
      </div>
      {onPage && (
        <div className="pagination">
          <span>
            {page
              ? `${number(page.total)} 条 · 第 ${Math.floor(page.offset / limit) + 1} / ${Math.max(1, Math.ceil(page.total / limit))} 页`
              : "尚无结果"}
          </span>
          <div>
            <Select
              label="每页记录数"
              value={String(limit)}
              onChange={(v) => onSize?.(Number(v))}
              options={[50, 100, 200].map((v) => ({
                value: String(v),
                label: `${v} / 页`,
              }))}
            />
            <Button
              variant="ghost"
              size="icon"
              aria-label="上一页"
              disabled={loading || !page || page.offset === 0}
              onClick={() => onPage(Math.max(0, (page?.offset || 0) - limit))}
            >
              <ChevronLeft size={15} />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              aria-label="下一页"
              disabled={loading || !page || page.offset + limit >= page.total}
              onClick={() => onPage((page?.offset || 0) + limit)}
            >
              <ChevronRight size={15} />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
