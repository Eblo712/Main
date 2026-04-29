"""
Генератор HTML-отчётов из JSON-файлов, созданных IDAPython-скриптом.
Не зависит от python-idb, работает с IDA Pro 9.3.
"""
import json
import logging
from pathlib import Path
from typing import Optional

try:
    from jinja2 import Environment, BaseLoader, select_autoescape
    _jinja2_available = True
except ImportError:
    _jinja2_available = False
    logging.error("Jinja2 не установлен. Установите: pip install jinja2")

logger = logging.getLogger(__name__)

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Отчёт: {{ file_name }}</title>
    <style>
        :root {
            --bg: #f5f5f5;
            --card-bg: white;
            --text: #303030;
            --accent: #007aff;
            --border: #d1d1d1;
            --hover: #f0f0f5;
        }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            margin: 30px;
            background: var(--bg);
            color: var(--text);
        }
        h1, h2 { color: var(--accent); }
        .search { margin-bottom: 20px; }
        .search input {
            width: 100%; padding: 12px; border: 1px solid var(--border);
            border-radius: 8px; font-size: 16px;
        }
        .card {
            background: var(--card-bg); border-radius: 12px;
            margin: 15px 0; padding: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .card-header {
            cursor: pointer; font-weight: 600;
            display: flex; justify-content: space-between; align-items: center;
        }
        .card-body { display: none; margin-top: 10px; }
        .card.open .card-body { display: block; }
        table {
            width: 100%; border-collapse: collapse; margin: 10px 0;
        }
        th, td {
            text-align: left; padding: 8px; border-bottom: 1px solid var(--border);
        }
        th { background: var(--hover); }
        .hexdump {
            font-family: monospace; white-space: pre-wrap;
            background: #f0f0f5; padding: 10px; border-radius: 6px; font-size: 13px;
        }
        .badge {
            display: inline-block; background: var(--accent); color: white;
            border-radius: 12px; padding: 2px 10px; font-size: 12px; margin-left: 8px;
        }
    </style>
</head>
<body>
    <h1>Отчёт анализа: {{ file_name }}</h1>

    <div class="search">
        <input type="text" id="quickSearch" placeholder="Поиск по функциям, импортам...">
    </div>

    <h2>Импортируемые функции <span class="badge">{{ imports|length }}</span></h2>
    <div class="card">
        <div class="card-header" onclick="this.parentElement.classList.toggle('open')">
            <span>Таблица импортов</span><span>▾</span>
        </div>
        <div class="card-body">
            {% if imports %}
            <table>
                <tr><th>Имя</th><th>Модуль</th><th>Адрес</th></tr>
                {% for imp in imports %}
                <tr class="searchable">
                    <td>{{ imp.name }}</td><td>{{ imp.module }}</td><td>{{ imp.address }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}<p>Нет импортируемых функций.</p>{% endif %}
        </div>
    </div>

    <h2>Дизассемблированные функции <span class="badge">{{ functions|length }}</span></h2>
    {% for func in functions %}
    <div class="card">
        <div class="card-header searchable" onclick="this.parentElement.classList.toggle('open')">
            <span>{{ func.name }} <small>({{ func.start_ea }}, размер: {{ func.size }} байт)</small></span>
            <span>▾</span>
        </div>
        <div class="card-body">
            <strong>Hex-дамп (первые 256 байт):</strong>
            <div class="hexdump">{{ func.hexdump }}</div>
            <strong>Дизассемблирование (первые 100 инструкций):</strong>
            <table>
                <tr><th>Адрес</th><th>Мнемоника</th><th>Операнды</th></tr>
                {% for insn in func.instructions %}
                <tr class="searchable">
                    <td>{{ insn.address }}</td><td>{{ insn.mnemonic }}</td><td>{{ insn.op_str }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </div>
    {% endfor %}

    <script>
        const searchInput = document.getElementById('quickSearch');
        searchInput.addEventListener('input', function() {
            const term = this.value.toLowerCase();
            document.querySelectorAll('.searchable').forEach(el => {
                el.style.display = el.textContent.toLowerCase().includes(term) ? '' : 'none';
            });
        });
        document.querySelectorAll('.card').forEach((card, index) => {
            if (index === 0) card.classList.add('open');
        });
    </script>
</body>
</html>"""

class ReportGenerator:
    """Создаёт HTML-отчёт из JSON-файла экспорта."""
    def __init__(self):
        if not _jinja2_available:
            raise ImportError("Jinja2 не установлен. Выполните: pip install jinja2")
        self.env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.template = self.env.from_string(REPORT_TEMPLATE)

    def generate_from_json(self, json_path: Path, output_html: Optional[Path] = None) -> Path:
        """Генерирует HTML из JSON-файла экспорта."""
        if not json_path.exists():
            raise FileNotFoundError(f"JSON-файл не найден: {json_path}")

        print(f"[ReportGenerator] Reading JSON: {json_path}")
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if output_html is None:
            output_html = json_path.with_suffix('.html')
        output_html.parent.mkdir(parents=True, exist_ok=True)

        html = self.template.render(data)
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[ReportGenerator] HTML saved: {output_html}")
        return output_html