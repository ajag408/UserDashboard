from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.home),
    url(r'^render_signin$', views.render_signin),
    url(r'^render_register$', views.render_register),
    url(r'^reg$', views.validate_register),
    url(r'^login$', views.login),
    url(r'^logout$', views.logout),
    url(r'^render_edit_profile$', views.render_edit_profile),
    url(r'^edit_info$', views.edit_info),
    url(r'^admin_edit_info/(?P<user_id>\d+)$', views.admin_edit_info),
    url(r'^change_pw$', views.change_pw),
    url(r'^admin_change_pw/(?P<user_id>\d+)$', views.admin_change_pw),
    url(r'^edit_description$', views.edit_description),
    url(r'^render_dashboard$', views.render_dashboard),
    url(r'^render_add_new$', views.render_add_new),
    url(r'^add_new$', views.add_new),
    url(r'^render_edit_user/(?P<user_id>\d+)$', views.render_edit_user),
    url(r'^render_user_page/(?P<user_id>\d+)$', views.render_user_page),
    url(r'^post_message/(?P<user_profile_id>\d+)$', views.post_message),
    url(r'^post_comment/(?P<message_id>\d+)/(?P<user_profile_id>\d+)$', views.post_comment)
]
