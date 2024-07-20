from django.db import models
from django.contrib.auth.models import User

#change comment in model

# Create your models here.
class Student(models.Model):
    name = models.CharField(max_length=20)
    age= models.IntegerField(default=18)
    def __str__(self):
        return self.name

class Payment(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE,null=True)
    name = models.CharField(max_length=100, blank=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    email = models.EmailField(null=False)
    phone = models.CharField(max_length=20)
    status = models.BooleanField(default=False)
    payment_id = models.CharField(max_length=100, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Payment #{self.id} - {self.user.username}'