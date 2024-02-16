from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User

# login form
class LoginForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(),
        error_messages={
            'required': 'This field is required.',
        },
    )
    password = forms.CharField(
        widget=forms.PasswordInput(),
        error_messages={
            'required': 'This field is required.',
        },
    )
# register form
class SignupForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('username','email' ,'password1', 'password2')
    username = forms.CharField(
        max_length=30,
        help_text="Required. 30 characters or fewer. Letters, digits, and @/./+/-/_ only.",
        error_messages={
            'required': 'This field is required.',
            'max_length': 'Username must be 30 characters or fewer.',
        }
    )
   
    email = forms.EmailField(
        max_length=254,
        help_text="Required. Enter a valid email address.",
        error_messages={
            'required': 'This field is required.',
            'invalid': 'Enter a valid email address.',
            'max_length': 'Email address must be 254 characters or fewer.',
        }
    )
   
    password1 = forms.CharField(
        widget=forms.PasswordInput(),
        help_text="Your password must contain at least 8 characters.",
        error_messages={'required': 'This field is required.'}
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(),
        help_text="Enter the same password as before, for verification.",
        error_messages={'required': 'This field is required.'}
    )
