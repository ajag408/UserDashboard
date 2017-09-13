from django.shortcuts import render, redirect
from models import *
import bcrypt
from django.contrib import messages
# Create your views here.
def home(request):

    return render(request, 'first_app/home.html')

def render_signin(request):
    return render(request, 'first_app/signin.html')

def render_register(request):
    return render(request, 'first_app/register.html')

def validate_register(request):
    check1 = User.objects.check_first_name(request.POST['first_name'])
    if check1 is False:
        messages.error(request, "First name: required; no fewer than 2 characters; letters only")
        return redirect('/render_register')

    check2 = User.objects.check_last_name(request.POST['last_name'])
    if check2 is False:
        messages.error(request, "Last name: required; no fewer than 2 characters; letters only")
        return redirect('/render_register')

    check3 = User.objects.check_email_1(request.POST['email'])
    if check3 is False:
        messages.error(request, "Email: Required; Valid Format")
        return redirect('/render_register')

    check6 = User.objects.check_email_2(request.POST['email'])
    if check6 is False:
        messages.error(request, 'email is already taken')
        return redirect('/render_register')

    check4 = User.objects.check_password_1(request.POST['password'])
    if check4 is False:
        messages.error(request, "Password: Required; No fewer than 8 characters in length")
        return redirect('/render_register')

    check5 = User.objects.check_password_2(request.POST['password'], request.POST['pconf'])
    if check5 is False:
        messages.error(request, "Password must match password confirmation")
        return redirect('/render_register')

    register = User.objects.register(request.POST['first_name'],request.POST['last_name'],request.POST['email'],request.POST['password'],request.POST['pconf'])
    if register is False:
        messages.error(request, "User already exists!")
        return redirect('/render_register')

    if register is True:
        this_user = User.objects.get(email = request.POST['email'])
        request.session['user'] = this_user.id
        return redirect('/render_dashboard')

def login(request):
    login = User.objects.login(request.POST['email'],request.POST['password'])
    if login is True:
        this_user = User.objects.get(email = request.POST['email'])
        request.session['user'] = this_user.id
        return redirect('/render_dashboard')
    else:
        messages.error(request, "Log-in failed: check email and password")
        return redirect('/render_signin')

def logout(request):
    if 'user' in request.session:
        del request.session['user']
    return redirect('/')

def render_dashboard(request):
    this_user = User.objects.get(id = request.session['user'])
    context = {
        'this_user': this_user,
        'users': User.objects.all()
    }
    if this_user.user_level == 'admin':
        return render(request, 'first_app/admin_dashboard.html', context)
    else:
        return render(request, 'first_app/user_dashboard.html', context)

def render_add_new(request):
    this_user = User.objects.get(id = request.session['user'])
    context = {
        'this_user': this_user
    }
    return render(request,'first_app/add_new.html', context)

def add_new(request):
    register = User.objects.register(request.POST['first_name'],request.POST['last_name'],request.POST['email'],request.POST['password'],request.POST['pconf'])
    if register is False:
        return redirect('/render_add_new')
    if register is True:
        return redirect('/render_dashboard')

def render_edit_profile(request):
    context = {
        'this_user': User.objects.get(id=request.session['user'])
    }
    return render(request, 'first_app/edit_profile.html', context)

def render_edit_user(request,user_id):
    this_user = User.objects.get(id = request.session['user'])
    edit_user = User.objects.get(id = user_id)
    context={
        'this_user': this_user,
        'edit_user': edit_user
    }
    return render(request, 'first_app/edit_user.html', context)

def edit_info(request):
    edit_user = User.objects.get(id=request.session['user'])
    edit_user.email = request.POST['email']
    edit_user.first_name = request.POST['first_name']
    edit_user.last_name = request.POST['last_name']
    edit_user.save()

    return redirect('/render_edit_profile')

def admin_edit_info(request,user_id):
    edit_user = User.objects.get(id= user_id)
    edit_user.email = request.POST['email']
    edit_user.first_name = request.POST['first_name']
    edit_user.last_name = request.POST['last_name']
    edit_user.user_level = request.POST['user_level']
    edit_user.save()

    return redirect('/render_edit_user/' + str(user_id))

def admin_change_pw(request,user_id):
    edit_user = User.objects.get(id=user_id)
    password = request.POST['password']
    password = password.encode()
    pw_hash = bcrypt.hashpw(password, bcrypt.gensalt())
    edit_user.pw_hash = pw_hash
    edit_user.save()

    return redirect('/render_edit_user/' + str(user_id))


def change_pw(request):
    user = User.objects.get(id=request.session['user'])
    password = request.POST['password']
    password = password.encode()
    pw_hash = bcrypt.hashpw(password, bcrypt.gensalt())
    user.pw_hash = pw_hash
    user.save()

    return redirect('/render_edit_profile')

def edit_description(request):
    user = User.objects.get(id=request.session['user'])
    user.description = request.POST['description']
    user.save()

    return redirect('/render_edit_profile')

def render_user_page(request,user_id):
    context={
        'user_profile': User.objects.get(id=user_id),
    }
    return render(request, 'first_app/user_page.html', context)

def post_message(request, user_profile_id):
    Message.objects.create(message_user_id = User.objects.get(id = request.session['user']), user_profile_id = User.objects.get(id = user_profile_id), message = request.POST['message'])
    return redirect('/render_user_page/' + str(user_profile_id))

def post_comment(request, message_id, user_profile_id):
    Comment.objects.create(message_id = Message.objects.get(id = message_id), comment_user_id = User.objects.get(id = request.session['user']), comment= request.POST['comment'])
    return redirect('/render_user_page/' + str(user_profile_id))
