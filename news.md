---
layout: default
title: News archive
---

## News archive

<br>
<ul>
{% for post in site.tags.news %}
<li>
<span> <time datetime="{{ post.date | date: "%Y-%m-%d" }}"> {{ post.date | date: "%Y-%m-%d" }} </time>  </span> 
<a href="{{ post.url }}">
{{ post.title }}
</a>
</li>
{% endfor %}
</ul>
