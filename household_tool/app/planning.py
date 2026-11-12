"""Deterministic Gantt layout, bounded independently of user-supplied dates.

Calendar-day, finish-to-start relationships; dates are inclusive. No automatic
rescheduling and no inferred start dates from deadlines/creation timestamps.
"""
from datetime import date

SCALES = {'day': (28, 42), 'week': (84, 20), 'month': (366, 7)}
MONTHS = ('Januar', 'Februar', 'März', 'April', 'Mai', 'Juni',
          'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember')
ROW_HEIGHT = 58


def build_plan(tasks, dependencies, milestones, today: date, anchor: str | None = None,
               scale: str = 'week') -> dict:
    scale = scale if scale in SCALES else 'week'
    days, day_width = SCALES[scale]
    tasks = [dict(t) for t in tasks if t['status'] != 'done']
    tasks.sort(key=lambda t: (t.get('start_date') is None, t.get('start_date') or '', t['id']))
    candidates = [date.fromisoformat(t['start_date']) for t in tasks if t.get('start_date')]
    candidates.extend(date.fromisoformat(m['due_date']) for m in milestones if m['due_date'])
    initial = min(candidates, default=today)
    start = date.fromisoformat(anchor) if anchor else initial
    first = max(1, min(start.toordinal(), date.max.toordinal() - days + 1))
    # Monday alignment unless that would leave the valid date range.
    first = max(1, first - date.fromordinal(first).weekday())
    start, end = date.fromordinal(first), date.fromordinal(first + days - 1)
    task_map = {t['id']: t for t in tasks}
    conflicts = []
    links_by_task = {}
    for dependency in dependencies:
        d = dict(dependency)
        links_by_task.setdefault(d['task_id'], []).append(d)
        target, source = task_map.get(d['task_id']), task_map.get(d['depends_on_task_id'])
        if target and source and target.get('start_date') and source.get('end_date'):
            if target['start_date'] <= source['end_date']:
                conflicts.append({'task_id': target['id'], 'title': target['title'],
                                  'source': source['title'], 'reason': 'dependency'})
    rows, positions = [], {}
    for task in tasks:
        row = dict(task)
        row['dependencies'] = links_by_task.get(task['id'], [])
        row['conflict'] = any(c['task_id'] == task['id'] for c in conflicts)
        row['scheduled'] = bool(task.get('start_date') and task.get('end_date'))
        row['visible'] = False
        row['deadline_x'] = None
        if row['scheduled']:
            a, b = date.fromisoformat(task['start_date']).toordinal(), date.fromisoformat(task['end_date']).toordinal()
            row['duration'] = b - a + 1
            row['visible'] = a <= first + days - 1 and b >= first
            row['x'] = (max(first, a) - first) * day_width
            row['width'] = max(0, (min(first + days, b + 1) - max(first, a)) * day_width)
            row['clipped_start'], row['clipped_end'] = a < first, b >= first + days
            if task.get('deadline') and task['end_date'] > task['deadline']:
                row['conflict'] = True
                conflicts.append({'task_id': task['id'], 'title': task['title'],
                                  'source': task['deadline'], 'reason': 'deadline'})
        if task.get('deadline'):
            deadline = date.fromisoformat(task['deadline']).toordinal()
            if first <= deadline < first + days:
                row['deadline_x'] = (deadline - first + .5) * day_width
        positions[task['id']] = len(rows)
        rows.append(row)
    paths = []
    for dependency in dependencies:
        source_id, target_id = dependency['depends_on_task_id'], dependency['task_id']
        if source_id not in positions or target_id not in positions:
            continue
        source, target = rows[positions[source_id]], rows[positions[target_id]]
        if not source['visible'] or not target['visible']:
            continue
        x1, x2 = source['x'] + source['width'], target['x']
        y1, y2 = positions[source_id] * ROW_HEIGHT + 29, positions[target_id] * ROW_HEIGHT + 29
        # Route outside the two bar endpoints; backwards links signal conflicts.
        elbow = min(days * day_width - 2, x1 + 10)
        d = f'M {x1} {y1} H {elbow} V {y2 - 21} H {max(2, x2 - 10)} V {y2} H {x2}'
        paths.append({'d': d, 'conflict': target['start_date'] <= source['end_date'],
                      'title': f"{source['title']} → {target['title']}"})
    milestone_rows = []
    for m in milestones:
        item = dict(m)
        item['visible'] = False
        if item['due_date']:
            ordinal = date.fromisoformat(item['due_date']).toordinal()
            item['visible'] = first <= ordinal < first + days
            item['x'] = (ordinal - first + .5) * day_width
        milestone_rows.append(item)
    ticks, months = [], []
    for offset in range(days):
        day = date.fromordinal(first + offset)
        if not months or months[-1]['key'] != (day.year, day.month):
            months.append({'key': (day.year, day.month), 'label': f'{MONTHS[day.month - 1]} {day.year}',
                           'short_label': f'{MONTHS[day.month - 1][:3]}. {day.year}',
                           'x': offset * day_width, 'width': day_width})
        else:
            months[-1]['width'] += day_width
        if scale == 'day' or day.weekday() == 0 and scale == 'week' or day.day == 1 and scale == 'month':
            tick_days = 1 if scale == 'day' else (7 if scale == 'week' else 28)
            ticks.append({'label': day.strftime('%d.%m.'), 'x': offset * day_width,
                          'width': min(days - offset, tick_days) * day_width})
    today_x = (today.toordinal() - first + .5) * day_width
    return {'rows': rows, 'paths': paths, 'milestones': milestone_rows, 'conflicts': conflicts,
            'scheduled_count': sum(r['scheduled'] for r in rows),
            'unscheduled_count': sum(not r['scheduled'] for r in rows),
            'scale': scale, 'days': days, 'day_width': day_width, 'width': days * day_width,
            'height': len(rows) * ROW_HEIGHT, 'row_height': ROW_HEIGHT,
            'start': start.isoformat(), 'end': end.isoformat(),
            'start_label': start.strftime('%d.%m.%Y'), 'end_label': end.strftime('%d.%m.%Y'),
            'prev': date.fromordinal(max(1, first - days)).isoformat(),
            'next': date.fromordinal(min(date.max.toordinal() - days + 1, first + days)).isoformat(),
            'today_x': today_x if 0 <= today_x < days * day_width else None,
            'ticks': ticks, 'months': months}
