from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail, EmailMessage
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from djangoProject import settings
from djangoProject.token import generatorToken


def home(request):
    return render(request, 'registration/index.html')


def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        firstname = request.POST.get('firstname')
        lastname = request.POST.get('lastname')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password1 = request.POST.get('password1')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Ce nom a été pris')
            return redirect('register')
        if not username.isalnum():
            messages.error(request, "le nom d'utilisateur doit être alphanumeric")
            return redirect('register')
        if password1 != password:
            messages.error(request, 'les mots de passe ne sont pas identiques')
            return redirect('register')
        monUtilisateur = User.objects.create_user(username, email, password)
        monUtilisateur.first_name = firstname
        monUtilisateur.last_name = lastname
        monUtilisateur.is_active = False
        monUtilisateur.save()
        messages.success(request, 'votre compte a été créé avec succés. Activez le ')

        # Envoie DE  MAIL
        sujet = "Bienvenue sur Nemeku!"
        message = "Bienvenue" + monUtilisateur.first_name + monUtilisateur.last_name + "\n Nous sommes ravis de vous compter parmi la communauté de Nemeku ! \n\n\n Merci \n\n l'équipe de support Nemeku"
        from_email = settings.EMAIL_HOST_USER
        to_email = [monUtilisateur.email]
        send_mail(sujet, message, from_email, to_email, fail_silently=True)

        # ENVOIE DE MAIL DE CONFIRMATION
        site_courant = get_current_site(request)
        email_subject = "Confirmation de l'adresse mail"
        messageConfirm = render_to_string("registration/emailconfirm.html",
                                          {
                                              'name': monUtilisateur.first_name,
                                              'domain': site_courant.domain,
                                              'uid': urlsafe_base64_encode(force_bytes(monUtilisateur.pk)),
                                              'token': generatorToken.make_token(monUtilisateur)
                                          })
        email = EmailMessage(
            email_subject, messageConfirm,
            settings.EMAIL_HOST_USER,
            [monUtilisateur.email]
        )
        email.fail_silently = False
        email.send()

        return redirect('login')
    return render(request, 'registration/signup.html')


def activate(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and generatorToken.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, "Compte bien activé !")
        return redirect('login')
    else:
        messages.error(request, "Erreur lors de l'activation")
        return redirect('home')


def logIn(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        myUser = User.objects.get(username=username)
        if user is not None:
            login(request, user)
            username = user.username
            return render(request, 'registration/index.html', {'username': username})
        elif myUser.is_active == False:
            messages.error(request, "Votre compte n'est pas activé")
            return redirect('login')
        else:
            messages.error(request, "Votre compte n'existe pas")
            return redirect('login')
    return render(request, 'registration/login.html')
def logout(request):
    messages.success(request,"Nemeku n'est rien sans vous ")
    return render(request,'registration/login.html')
