from django.db import connection
from django.http import HttpResponse, HttpResponseRedirect
from django.views.decorators.csrf import csrf_exempt


def profile(request, user_id):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM auth_user WHERE id = " + user_id)  # SQL injection: user_id is text from the URL
        return HttpResponse(cursor.fetchone())


def greet(request):
    return HttpResponse("Hello " + request.GET["name"])  # XSS


def leave(request):
    return HttpResponseRedirect(request.GET.get("to"))  # open redirect


@csrf_exempt
def webhook(request):
    return HttpResponse("ok")
