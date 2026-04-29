"""
Генератор HTML-отчётов из JSON-файлов, созданных IDAPython-скриптом.
Не зависит от python-idb, работает с IDA Pro 9.3.
"""
import json
import logging
from pathlib import Path
from typing import Optional, List
from collections import defaultdict

try:
    from jinja2 import Environment, BaseLoader, select_autoescape
    _jinja2_available = True
except ImportError:
    _jinja2_available = False
    logging.error("Jinja2 не установлен. Установите: pip install jinja2")

from .module_classifier import classify_category

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Шаблон ОДНОГО отчёта (без категорий, без описаний – как было изначально)
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Шаблон СВОДНОГО ИНДЕКСА (с категориями модулей)
# ---------------------------------------------------------------------------
INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Индекс отчётов анализа</title>
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
        .card {
            background: var(--card-bg); border-radius: 12px;
            margin: 15px 0; padding: 15px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        a { color: #007aff; text-decoration: none; font-weight: 500; }
        a:hover { text-decoration: underline; }
        ul { padding-left: 20px; }
        .badge {
            display: inline-block; background: var(--accent); color: white;
            border-radius: 12px; padding: 2px 10px; font-size: 12px; margin-left: 8px;
        }
        .module-list { column-count: 2; }
        .ida-info { font-size: 13px; color: #666; margin-top: 10px; }
    </style>
</head>
<body>
    <h1>Сводный отчёт анализа</h1>

    <div class="card">
        <h2>Сгенерированные отчёты <span class="badge">{{ total_reports }}</span></h2>
        <ul>
            {% for report in reports %}
            <li><a href="{{ report.link }}">{{ report.name }}</a></li>
            {% endfor %}
        </ul>
    </div>

    <div class="card">
        <h2>Использованные модули <span class="badge">{{ modules|length }}</span></h2>
        <div class="module-list">
            <ul>
                {% for mod, cat, desc in modules_with_categories %}
                <li>{{ mod }} <span style="color: #888;">[{{ cat }}]</span>{% if desc %} — {{ desc }}{% endif %}</li>
                {% endfor %}
            </ul>
        </div>
    </div>

    {% if ida_info %}
    <div class="card">
        <h2>Информация об IDA Pro</h2>
        <div class="ida-info">{{ ida_info }}</div>
    </div>
    {% endif %}
</body>
</html>"""

class ReportGenerator:
    """Создаёт HTML-отчёты из JSON-файла экспорта."""
    def __init__(self):
        if not _jinja2_available:
            raise ImportError("Jinja2 не установлен. Выполните: pip install jinja2")
        self.env = Environment(
            loader=BaseLoader(),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.report_template = self.env.from_string(REPORT_TEMPLATE)
        self.index_template = self.env.from_string(INDEX_TEMPLATE)

    def generate_from_json(self, json_path: Path, output_html: Optional[Path] = None) -> Path:
        """
        Генерирует индивидуальный HTML-отчёт по JSON-файлу.
        Без категорий, только сырые импорты и функции.
        """
        if not json_path.exists():
            raise FileNotFoundError(f"JSON-файл не найден: {json_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Данные передаются как есть – никакой классификации
        if output_html is None:
            output_html = json_path.with_suffix('.html')
        output_html.parent.mkdir(parents=True, exist_ok=True)

        html = self.report_template.render(data)
        with open(output_html, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML-отчёт сохранён: {output_html}")
        return output_html

    def generate_index(self, reports_dir: Path, input_dir: Path,
                       generated_html_files: List[Path],
                       sorted_modules: List[str],
                       ida_info: Optional[str] = None):
        """
        Создаёт сводный индексный файл index.html с категоризацией модулей.
        """
        reports = []
        for html_path in generated_html_files:
            reports.append({
                "link": html_path.name,
                "name": html_path.stem
            })

        # Классифицируем модули для сводной страницы
        modules_with_categories = []
        for mod in sorted_modules:
            cat, desc = classify_category(mod)
            modules_with_categories.append((mod, cat, desc))

        index_path = reports_dir / "index.html"
        html = self.index_template.render(
            total_reports=len(reports),
            reports=reports,
            modules=sorted_modules,
            modules_with_categories=modules_with_categories,
            ida_info=ida_info.replace("\n", "<br>") if ida_info else None
        )
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"Индексный файл сохранён: {index_path}")