# {{ title }}

{% for chunk in chunks %}
## {{ chunk.title }}

Target: {{ chunk.target }}

Total items: {{ chunk.total_item_count }}

| GUID         | Name         | Note         |
|--------------|--------------|--------------|
{% for item in chunk.item_view -%}
| {{ item.guid }} | {{ item.name or 'N/A' }} | {{ item.note or 'N/A' }} |
{% endfor %}
{% endfor %}
