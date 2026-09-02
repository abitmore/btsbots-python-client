import sqlite3
import datetime
import argparse

def format_timestamp(ts):
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

def view_audit_logs(db_path: str = "bots.sqlite", limit: int = 20):
    try:
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # 检查表是否存在
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs';")
            if not cursor.fetchone():
                print("❌ 暂未发现审计日志表 (audit_logs)。请先运行 sign_bots.py 产生交易或鉴权请求。")
                return

            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()

            if not rows:
                print("📭 审计日志为空。")
                return

            print("=" * 90)
            print(f"📋 BTSBots 安全审计日志查看器 (最近 {len(rows)} 条记录)")
            print("=" * 90)

            for row in rows:
                time_str = format_timestamp(row["timestamp"])
                status_icon = "✅" if row["status"] == "SUCCESS" else ("🟢" if row["status"] == "APPROVED" else "❌")

                print(f"[{row['id']}] {time_str} | 账号: {row['account_name']} | 设备: {row['device_alias']}")
                print(f" └─ 类型: {row['op_type']} | 状态: {status_icon} {row['status']}")
                print(f" └─ 详情: {row['detail']}")
                if row["raw_summary"] and row["raw_summary"] != "{}":
                    print(f" └─ 摘要: {row['raw_summary']}")
                print("-" * 90)

    except Exception as e:
        print(f"❌ 读取审计日志发生错误: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="查看 BTSBots 签名网关安全审计日志")
    parser.add_argument("--db", type=str, default="bots.sqlite", help="SQLite 数据库路径")
    parser.add_argument("--limit", type=int, default=20, help="显示最近多少条记录")
    args = parser.parse_args()

    view_audit_logs(db_path=args.db, limit=args.limit)
