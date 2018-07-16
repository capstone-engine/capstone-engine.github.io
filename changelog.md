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
<div class="date"> {{ post.date | date: "%e-%b-%Y" }} </div>

{{ post.content }}
</article>
{% endfor %}

