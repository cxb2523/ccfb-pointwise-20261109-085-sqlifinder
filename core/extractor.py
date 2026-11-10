import re
from html.parser import HTMLParser
from urllib.parse import urljoin

# Caps so request volume cannot explode with field * payload * retries.
MAX_FORMS_PER_PAGE = 5
MAX_FIELDS_PER_FORM = 10

# Control/UI elements are never standalone injection points.
_SKIPPED_INPUT_TYPES = {'submit', 'button', 'reset', 'image'}


def param_extract(response, level, black_list, placeholder):
    r"""
    Extract URL parameters from response text and replace values with placeholders.

    Args:
        response (str): HTML/text response to parse for URLs with parameters
        level (str): Depth of parameter extraction ('high' extracts nested params)
        black_list (list): List of strings to exclude from results
        placeholder (str): String to replace parameter values with

    Returns:
        list: Unique URLs with parameter values replaced by placeholder

    Uses regex patterns:
        - r'.*?:\/\/.*\?.*\=[^$]' : Matches URLs with at least one parameter
        - r'.*?:\/\/.*\?.*\=' : Basic URL parameter pattern
    """

    r'''
    regexp : r'.*?:\/\/.*\?.*\=[^$]'
    regexp : r'.*?:\/\/.*\?.*\='
    '''

    parsed = list(set(re.findall(r'.*?:\/\/.*\?.*\=[^$]', response)))
    final_uris = []

    for i in parsed:
        delim = i.find('=')
        second_delim = i.find('=', delim + 1)
        if len(black_list) > 0:
            words_re = re.compile("|".join(black_list))
            if not words_re.search(i):
                final_uris.append((i[:delim+1] + placeholder))
                if level == 'high' and second_delim > delim:
                    final_uris.append(i[:second_delim+1] + placeholder)
        else:
            final_uris.append((i[:delim+1] + placeholder))
            if level == 'high' and second_delim > delim:
                final_uris.append(i[:second_delim+1] + placeholder)

    # for i in final_uris:
    #     k = [ele for ele in black_list if(ele in i)]

    return list(set(final_uris))


class _FormParser(HTMLParser):
    """Collect forms and their fields from one HTML page."""

    def __init__(self, base_url, max_forms=MAX_FORMS_PER_PAGE,
                 max_fields=MAX_FIELDS_PER_FORM):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.max_forms = max_forms
        self.max_fields = max_fields
        self.forms = []
        self._current = None
        self._select_name = None
        self._textarea_name = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == 'form':
            # Stop opening new forms once the per-page cap is reached.
            if len(self.forms) >= self.max_forms:
                self._current = None
                return
            action = attrs.get('action') or self.base_url
            self._current = {
                'action': urljoin(self.base_url, action),
                'method': (attrs.get('method') or 'GET').upper(),
                # name -> default value; dict doubles as per-form dedup.
                'fields': {},
            }
            self._select_name = None
            self._textarea_name = None
            return

        if self._current is None:
            return

        if tag == 'input':
            name = attrs.get('name')
            input_type = (attrs.get('type') or 'text').lower()
            # submit/button/reset/image are controls, not injectable fields.
            if not name or input_type in _SKIPPED_INPUT_TYPES:
                return
            if len(self._current['fields']) >= self.max_fields:
                return
            # Hidden inputs and pre-filled defaults are kept verbatim.
            self._current['fields'].setdefault(name, attrs.get('value', ''))

        elif tag == 'select':
            name = attrs.get('name')
            if name and name not in self._current['fields'] \
                    and len(self._current['fields']) < self.max_fields:
                self._current['fields'][name] = ''
                self._select_name = name

        elif tag == 'option' and self._select_name is not None:
            value = attrs.get('value', '')
            stored = self._current['fields'].get(self._select_name, '')
            # First option is the default; a `selected` option overrides it.
            if 'selected' in attrs or stored == '':
                self._current['fields'][self._select_name] = value

        elif tag == 'textarea':
            name = attrs.get('name')
            if name and name not in self._current['fields'] \
                    and len(self._current['fields']) < self.max_fields:
                self._current['fields'][name] = ''
                self._textarea_name = name

        # A bare <button> is a control and is deliberately ignored.

    def handle_endtag(self, tag):
        if tag == 'form' and self._current is not None:
            self.forms.append(self._current)
            self._current = None
            self._select_name = None
            self._textarea_name = None
        elif tag == 'select':
            self._select_name = None
        elif tag == 'textarea':
            self._textarea_name = None

    def handle_data(self, data):
        if self._current is not None and self._textarea_name is not None:
            previous = self._current['fields'].get(self._textarea_name, '')
            self._current['fields'][self._textarea_name] = previous + data


def form_extract(html, base_url, max_forms=MAX_FORMS_PER_PAGE,
                 max_fields=MAX_FIELDS_PER_FORM):
    """
    Parse forms out of a page and expand them into POST injection points.

    For every POST form, each named field (hidden fields and default values
    included) yields one injection point where only that field is replaced by
    the payload while every other field is sent with its original value.
    submit/button/reset/image controls are never tested. Points are
    de-duplicated and the number of forms/fields per page is capped.

    Args:
        html (str): Raw HTML of the page.
        base_url (str): Page URL used to resolve relative form actions.
        max_forms (int): Maximum number of forms considered per page.
        max_fields (int): Maximum number of fields kept per form.

    Returns:
        list[dict]: Each item is {'action', 'method', 'fields', 'target'}
        where 'fields' is the full original name->value mapping and 'target'
        is the single field to inject into.
    """
    parser = _FormParser(base_url, max_forms=max_forms, max_fields=max_fields)
    try:
        parser.feed(html or '')
    except Exception:
        # Malformed markup should never break the scan.
        return []

    points = []
    seen = set()
    for form in parser.forms:
        if form['method'] != 'POST':
            # GET forms are already covered by the query-parameter pipeline.
            continue
        field_names = tuple(sorted(form['fields'].keys()))
        for target in field_names:
            key = (form['action'], form['method'], field_names, target)
            if key in seen:
                continue
            seen.add(key)
            points.append({
                'action': form['action'],
                'method': form['method'],
                'fields': dict(form['fields']),
                'target': target,
            })
    return points
