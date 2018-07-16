---
layout: default
title: Version history
---

## Version history
{% for post in site.tags.changelog %}
---
<article>
<a href="{{ post.url }}">
<h3>Version {{ post.title }}</h3>
</a>
<time datetime="{{ post.date | date: "%Y-%m-%d" }}">
</time>
<div class="date">
<div class="dateday">{{ post.date | date: "%e" }}</div>
<div>{{ post.date | date: "%b" }}</div>
<div class="dateyear">{{ post.date | date: "%Y" }}</div>
</div>

{{ post.content }}
</article>
{% endfor %}

