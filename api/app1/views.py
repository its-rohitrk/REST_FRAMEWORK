from django.shortcuts import render,HttpResponse,redirect
from django.http import JsonResponse
from rest_framework.response import Response
from rest_framework.decorators import api_view
from .models import *
from .serializers import *
from django.contrib.auth.models import User

from  rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework.authentication import SessionAuthentication, BasicAuthentication


class StudentAPI(APIView):
    #authentication_classes = [SessionAuthentication, BasicAuthentication]
    #permission_classes = [IsAdminUser]

    def get(self, request):
        stu_obj = Student.objects.all()
        serializer = StudentSerializers(stu_obj, many=True)

        return Response({"status": 200, "paylod": serializer.data})

    def post(self,request):
        serializer = StudentSerializers(data=request.data)
        if not serializer.is_valid():
            return Response({"status": 403, "error": serializer.errors, "message": "something went wrong"})

        serializer.save()

        return Response({"status": 200, "data": serializer.data, "message": "successfully"})


    def put(self,request):
        try:
            stu_obj = Student.objects.get(id=request.data['id'])
            # print("##################",stu_obj)

            serializer = StudentSerializers(stu_obj, data=request.data)
            if not serializer.is_valid():
                return Response({"status": 403, "error": serializer.errors, "message": "something went wrong"})

            serializer.save()
            return Response({"status": 200, "data": serializer.data, "message": "your data updated."})


        except Exception as e:
            return Response({"status": 403, "message": "invalid id"})


    def patch(self,request):
        try:
            stu_obj = Student.objects.get(id=request.data['id'])
            # print("##################",stu_obj)

            serializer = StudentSerializers(stu_obj, data=request.data, partial=True)
            if not serializer.is_valid():
                return Response({"status": 403, "error": serializer.errors, "message": "something went wrong"})

            serializer.save()
            return Response({"status": 200, "data": serializer.data, "message": "your data updated."})


        except Exception as e:
            return Response({"status": 403, "message": "invalid id"})


    def delete(self,request):
        id = request.GET.get("id")
        print("##############3",id)
        # stu_obj = Student.objects.get(id=id)

        # print("@@@@@@@@@@@@@@@@@@@@2",stu_obj)
        #stu_obj.delete()
        return Response({"status": 200, "message": "deleted."})
        # except Exception as e:
        #     return ({"status": "403", "message": "ivalid id"})



from django.contrib.auth.forms import UserCreationForm
# from .forms import SignUp
# def signup(request):
#     if request.method == 'POST':
#         form = SignUp(request.POST)
#         if form.is_valid():
#             user = form.save(commit=False)
#             user.is_active = False  # Set user as inactive until email is verified
#             user.save()
#             send_verification_email(request, user)
#             return HttpResponse('Account created. Please check your email for verification instructions.')
#     else:
#         form = SignUp()
#     return render(request, 'register.html', {'form': form})
#
#
# def login1(request):
#     return render(request, 'login.html')
#
from django.core.mail import send_mail
from django.conf import settings

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
#
#
# def send_verification_email(request,user):
#     token = default_token_generator.make_token(user)
#     uid = urlsafe_base64_encode(force_bytes(user.pk))
#     # print("####",uid)
#     reset_url = request.build_absolute_uri(f"/reset-password/{uid}/{token}/")
#     #send_password_reset_email(user.email, reset_url)
#     subject = 'Password Reset'
#     message = f'Click the link below to reset your password:\n\n{reset_url}'
#     from_email = settings.EMAIL_HOST_USER
#     recipient= user.email
#     send_mail(subject, message, from_email,[recipient])
#     return HttpResponse("we have sent email to you.please check.")
#
#
# def verify_email(request, uidb64, token):
#     uid = force_text(urlsafe_base64_decode(uidb64))
#     user = User.objects.get(pk=uid)
#     if user is not None and default_token_generator.check_token(user, token):
#         if user.is_active==True:
#             return HttpResponse("already verified")
#         else:
#             user.is_active = True
#             user.save()
#             return redirect('/login')
#     else:
#         return HttpResponse('error')
#















# class testApi(APIView):
#     global var
#     var = ""
#     def get(self,request):
#         return Response({"status": 200,"var":var})
#
#     def post(self,request):
#         varr = request.POST.get("var")
#         print(varr)
#         return Response({"status": 403,"var":varr})

# from rest_framework.response import Response
# from rest_framework.views import APIView
#
# class testApi(APIView):
#     global var
#     var = ""
#
#     def get(self, request):
#         return Response({"status": 200, "var": var})
#
#     def post(self, request):
#         varr = request.data.get("var")  # Retrieve data from request body
#         print(varr)
#
#         # Set the global variable var
#         self.var = varr
#
#         return Response({"status": 200, "var": varr})
#
#
# from django.shortcuts import render,redirect
#
# def your_view(request):
#     return render(request, 'test1.html')


from django.views import  View
from .forms import StudentForm
class Home(View):

    def get(self,request):
     form = StudentForm()
     return render(request,"home.html",{"form":form})
    def post(self,request):
        form = StudentForm(data = request.POST)
        if form.is_valid():
            form.save()
            return HttpResponse("form submitted")





















# Create your views here.
# @api_view(['GET'])
# def stu_data(request):
#     stu_obj = Student.objects.all()
#     serializer = StudentSerializers(stu_obj,many=True)
#     return Response({"status":200,"paylod":serializer.data})
#
# @api_view(['POST'])
# def post_stu(request):
#     data = request.data
#     serializer = StudentSerializers(data = request.data)
#     if not serializer.is_valid():
#         return Response({"status": 403, "error":serializer.errors,"message": "something went wrong"})
#
#     serializer.save()
#
#     return Response({"status":200,"data":serializer.data,"message":"successfully"})
#
#
#
#
#
# @api_view(["PATCH"])
# def put_stu(request,id):
#     try:
#         stu_obj = Student.objects.get(id=id)
#         #print("##################",stu_obj)
#
#         serializer = StudentSerializers(stu_obj,data = request.data,partial=True)
#         if not serializer.is_valid():
#             return Response({"status": 403, "error":serializer.errors,"message": "something went wrong"})
#
#         serializer.save()
#         return Response({"status": 200, "data": serializer.data, "message": "your data updated."})
#
#
#     except Exception as e:
#         return Response({"status":403,"message":"invalid id"})
#
#
#
# @api_view(['DELETE'])
# def delete_stu(request,id):
#     try:
#         stu_obj = Student.objects.get(id=id)
#         stu_obj.delete()
#         return Response({"status":200,"message":"deleted."})
#     except Exception as e:
#         return ({"status":"403","message":"ivalid id"})

from django.http import HttpResponse
import geocoder
def get_ip(request):
    # ip_address = request.META.get('REMOTE_ADDR')
    g = geocoder.ip('203.190.154.86')
    loc_data = g.latlng
    data = {
        'latitude': loc_data[0],
        'longitude': loc_data[1]
    }
    # loc={"loc":loc_data}
    return JsonResponse(data)


def map(request):
    return render(request,"map.html")



from django.contrib import messages

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserSerializer, LoginSerializer
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.decorators import login_required



class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        print(serializer)
        if serializer.is_valid():
            user = serializer.save()
            send_verification_email(request,user)
            print("*********",user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            user = authenticate(username=username, password=password)
            #print("#################",user)
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def send_verification_email(request,user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    # print("####",uid)
    verify_url = request.build_absolute_uri(f"/verify/{uid}/{token}/")
    #send_password_reset_email(user.email, reset_url)
    subject = 'verification email'
    message = f'Click the link below to enter test software:\n\n{verify_url}'
    from_email = settings.EMAIL_HOST_USER
    recipient= user.email
    send_mail(subject, message, from_email,[recipient])
    return HttpResponse("we have sent email to you.please check.")


def verify_email(request, uidb64, token):
    uid = force_text(urlsafe_base64_decode(uidb64))
    user = User.objects.get(pk=uid)
    if user is not None and default_token_generator.check_token(user, token):
        if user.is_active==True:
            return HttpResponse("already verified")
        else:
            user.is_active = True
            user.save()
            user_obj1 = User.objects.filter(username=str(user)).first()

            #
            login(request, user_obj1)
            return redirect('/home/')
            print("#################", user_obj1)
            #return redirect('/home/')

    else:
        return HttpResponse('error')


def is_valid_username(username):
    return len(username) >= 4  # Example validation, adjust as needed

def is_valid_password(password):
    # Add more sophisticated password validation if needed
    return len(password) >= 4




# views.py
from django.shortcuts import render, redirect
import requests

def user_registration(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        if username=="":
            messages.error(request, " please enter  username", extra_tags='signup-error')
            return redirect("register")

        if not is_valid_username(username):
            messages.error(request, "Username must be at least 5 characters long.", extra_tags='signup-error')
            return redirect("register")  # Assuming you have a registration page

        # Validate password length and character requirements
        if not is_valid_password(password):
            messages.error(request,
                           "Password must be at least 8 characters long and contain at least one alphanumeric character and one special character.",
                           extra_tags='signup-error')
            return redirect("register")
        data = {'username': username, 'email': email, 'password': password}
        response = requests.post('http://127.0.0.1:8000/api/register/', data=data)
        if response.status_code == 201:  # Assuming 201 is the status code for successful user creation
            return redirect('massage')  # Redirect to login page after successful registration
        else:
            return HttpResponse("erooor............")
    return render(request, 'signin.html')




def massage1(request):
    name = request.user.username
    print("###############",name)
    return render(request,"email.html",{"name":name})

from datetime import timedelta
def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        remember_me = request.POST.get("remember_me") == "on"
        user_obj = User.objects.filter(username=username).first()

        if not User.objects.filter(username__iexact=username).exists():
            messages.error(request, "Invalid username", extra_tags="signin-error")
            print("#####################################")
            return redirect("/login/")
            #return HttpResponse("Invalid username")

        #user_obj = authenticate(username=username, password=password)

        if user_obj:  # If the user exists
            if user_obj.check_password(password):  # Check if password is correct000000
                data = {'username': username, 'password': password}
                response = requests.post('http://127.0.0.1:8000/api/login/', data=data)
                print("%%%%%%%%%%",response)

                if response.status_code == 200:  # Assuming 200 is the status code for successful login
                    # Redirect to user dashboard or home page
                    login(request, user_obj)
                    if remember_me:
                        request.session.set_expiry(settings.REMEMBER_ME_DURATION)
                    else:
                        request.session.set_expiry(0)


                    return redirect('/home/')  # Example: Redirect to user dashboard
                else:
                    return redirect('/register/')
            else:
                messages.error(request, "Invalid password", extra_tags="signin-error")
                # Redirect back to login page with error message
                return redirect('/register/')
        else:
            messages.error(request, "User does not exist", extra_tags="signin-error")
            # Redirect back to login page with error message
            return redirect('/register/')

    return render(request, 'signin.html')


@login_required(login_url="login")
def home(request):
    return render(request,'index.html')



@login_required(login_url="/login/")

def whyus(request):
    return render(request,'why.html')




@login_required(login_url="/login/")

def trainer(request):
    return render(request,'trainer.html')

#@login_required(login_url="/login/")

# def contactus(request):
#     if request.method=='POST':
#         name = request.POST.get("name")
#         email = request.POST.get("email")
#         phone = request.POST.get("phone")
#         message = request.POST.get("message")
#
#         print("##########################",name,email,phone,message)

#    return render(request,'contact.html')
from django.http import JsonResponse
import razorpay

def get_razorpay_client():
    return razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
@login_required(login_url="/login/")
def fees(request):
    if request.method == 'POST':
        # Extract data from the POST request
        name = request.POST.get("name")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        message = request.POST.get("message")
        amount = int(request.POST.get("amount")) * 100 # Convert amount to paise (assuming amount is in rupees)



        # Initialize Razorpay client
        client = get_razorpay_client()

        # Create order
        order_params = {
            'amount': amount,
            'currency': 'INR',
            #'receipt': 'order_rcptid_11',
            'payment_capture': 1
        }
        gymfees = client.order.create(data=order_params)
        print(gymfees)
        payment = Payment(name=name, amount=amount/100, phone=phone, email=email, payment_id=gymfees["id"],
                          user_id=request.user.id)
        payment.save()

        currency = 'INR'
        razorpay_order_id = gymfees['id']
        callback_url = '/success/'

        context = {}
        context['razorpay_order_id'] = razorpay_order_id
        context['razorpay_merchant_key'] = settings.RAZORPAY_KEY_ID
        context['razorpay_amount'] = amount
        context['currency'] =currency
        context['callback_url'] = callback_url
        context['razor_name']="Gym fess"



        return render(request, 'contact.html', context=context)



        # Return order ID and amount to the frontend
        #return JsonResponse({'order_id': order['id'], 'amount': amount // 100})

    return render(request, 'contact.html')



@csrf_exempt
@login_required(login_url="/login/")
def success(request):
    if request.method=='POST':
        payment_id = request.POST.get('razorpay_payment_id', '')
        razorpay_order_id = request.POST.get('razorpay_order_id', '')
        signature = request.POST.get('razorpay_signature', '')

        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': payment_id,
            'razorpay_signature': signature
        }
        client = get_razorpay_client()
        try:
            # Verify payment signature
            result = client.utility.verify_payment_signature(params_dict)
            if result is not None:
                # Signature verification successful
                user = Payment.objects.filter(payment_id=razorpay_order_id).first()
                if user:
                    user.status = True  # Update payment status
                    user.save()
                    return render(request, 'success.html')
                else:
                    return render(request, 'error.html')
            else:
                # Signature verification failed
                return render(request, 'error.html')
        except Exception as e:
            # Handle any exceptions that occur during signature verification
            print("Exception:", str(e))
            return render(request, 'error.html')

        return HttpResponse(status=400)  # Return a bad request if method is not POST

    #     print("############77", params_dict)
    #     client = get_razorpay_client()
    #     result = client.utility.verify_payment_signature(
    #         params_dict)
    #
    #     print("############3",result)
    #
    #     #if result is not None:
    #
    #
    #     user = Payment.objects.filter(payment_id = razorpay_order_id).first()
    #     user.status=True
    #     user.save()
    #
    # return render(request,'success.html')





@csrf_exempt
def paymenthandler(request):
    # only accept POST request.
    if request.method == "POST":
        try:

            # get the required parameters from post request.
            payment_id = request.POST.get('razorpay_payment_id', '')
            razorpay_order_id = request.POST.get('razorpay_order_id', '')
            signature = request.POST.get('razorpay_signature', '')
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            }

            print(params_dict)

            # verify the payment signature.
            result = razorpay_client.utility.verify_payment_signature(
                params_dict)
            if result is not None:
                amount = 20000  # Rs. 200
                try:

                    # capture the payemt
                    razorpay_client.payment.capture(payment_id, amount)

                    # render success page on successful caputre of payment
                    return render(request, 'paymentsuccess.html')
                except:

                    # if there is an error while capturing payment.
                    return render(request, 'paymentfail.html')
            else:

                # if signature verification fails.
                return render(request, 'paymentfail.html')
        except:

            # if we don't find the required parameters in POST data
            return HttpResponseBadRequest()
    else:
        # if other than POST request is made.
        return HttpResponseBadRequest()





@login_required(login_url="/login/")

def logout_page(request):
    request.session.flush()
    logout(request)
    return redirect('login')



# views.py


from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponseBadRequest

# authorize razorpay client with API Keys.
razorpay_client = razorpay.Client(
    auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))


# def homepage(request):
#     currency = 'INR'
#     amount = 20000  # Rs. 200
#
#     # Create a Razorpay Order
#     razorpay_order = razorpay_client.order.create(dict(amount=amount, currency=currency,payment_capture='0'))
#
#     # order id of newly created order.
#     razorpay_order_id = razorpay_order['id']
#     callback_url = 'paymenthandler/'
#
#     # we need to pass these details to frontend.
#     context = {}
#     context['razorpay_order_id'] = razorpay_order_id
#     context['razorpay_merchant_key'] = settings.RAZORPAY_KEY_ID
#     context['razorpay_amount'] = amount
#     context['currency'] = currency
#     context['callback_url'] = callback_url
#
#     return render(request, 'payment.html', context=context)


# we need to csrf_exempt this url as
# POST request will be made by Razorpay
# and it won't have the csrf token.


def forget_pass(requset):
    if requset.method=="POST":
        email = requset.POST.get("email")
        user = User.objects.filter(email=email).first()
        if user:
            token = default_token_generator.make_token(user)
            uuiid = urlsafe_base64_encode(force_bytes(user.pk))
            reset_url = requset.build_absolute_uri(f"/reset_password/{token}/{uuiid}/")
            subject = 'Password Reset'
            message = f'Click the link below to reset your password:\n\n{reset_url}'
            from_email = settings.EMAIL_HOST_USER
            send_mail(subject, message, from_email, [email])
            messages.success(requset, "Password reset email sent. Check your inbox.")

        else:
            messages.error(requset, "No user found with this email address.")
        return redirect("/forget_password/")

    return render(requset,"forget.html")


def reset_password(request,uidb64,token):
    if request.method=="POST":

        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        if default_token_generator.check_token(user,token):
            new_password = request.POST.get("pwd")
            re_password = request.POST.get("pwd1")

            if len(new_password) >= 8 and new_password == re_password:
                user.set_password(new_password)
                user.save()
                messages.success(request, "Password reset successful. You can now login with your new password.")
                return redirect("/changed/")

            elif len(new_password)<8:

                messages.error(request, "Passwords must match and be at least 8 characters long.")
                # return redirect("/reset-password/{}/{}/".format(uidb64, token))

            elif new_password != re_password:
                messages.error(request, "Please re enter same password...")
                # return redirect("/reset-password/{}/{}/".format(uidb64, token))
        else:
            messages.error(request,"Invalid token")
    return render(request,"password_reset.html")

def pass_change(request):
    return render(request,"succespass.html")