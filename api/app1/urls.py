from django.contrib import admin
from django.urls import path,include
from .views import *
#from app1 import views

urlpatterns = [


    # path('student/', StudentAPI.as_view()),
    #path('test', testApi.as_view(),name="api_test"),
    # path("home/",Home.as_view(),name="home"),
    #path("register/",signup),
    #path("login/",login1),
# path("get_ip/",get_ip),
    # path("map/",map),
    path('send-verification-email/', send_verification_email, name='send_verification_email'),
    path('verify/<str:uidb64>/<str:token>/', verify_email, name='verify_email'),
    path("massage/",massage1,name="massage"),


    path('api/register/', RegisterView.as_view(), name='registerapi'),
    path('api/login/', LoginView.as_view(), name='loginapi'),
    path('login/',user_login, name='login'),
    path('register/', user_registration, name='register'),
    #path("home/",login_required(home),name="home"),
    path("home/",home,name="home"),
    path("whyus/",whyus,name="whyus"),
    path("trainer/",trainer,name="trainer"),
    path("contact/",fees,name="contact"),
    path("logout/",logout_page,name="logout_page"),
    #path('', homepage, name='home'),
    # path('', homepage, name='index'),
    path('paymenthandler/',paymenthandler, name='paymenthandler'),
    path('success/',success, name='success'),
    path("forget_password/",forget_pass,name="forget_password"),
    path("reset_password/<str:token>/<str:uidb64>/",reset_password,name="reset_password"),
    path("changed/",pass_change,name="changed")



    #path('reset-password/<str:uidb64>/<str:token>/', reset_password, name='reset_password')
    # path('', stu_data),
    # path("post_data",post_stu),
    # path("stu_update/<id>/",put_stu),
    # path("stu_delete/<id>/",delete_stu),
]