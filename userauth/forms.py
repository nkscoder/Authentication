from django import forms


class ChangePasswordForm(forms.Form):
    """form for the change password"""
    old_password = forms.CharField(label="Password", widget=forms.PasswordInput(
        attrs={"placeholder": "Old Password", "class": "width-100"}, render_value=True),)
    new_password = forms.CharField(label="Password", widget=forms.PasswordInput(
        attrs={"placeholder": "New Password", "class": "width-100"}, render_value=True),)
    retype_password = forms.CharField(label="Confirm Password", widget=forms.PasswordInput(
        attrs={"placeholder": "Repeat Password", "class": "width-100"}, render_value=True))


class ResetPasswordForm(forms.Form):
    """form for the reset password"""
    new_password = forms.CharField(label="Password", widget=forms.PasswordInput(
        attrs={"placeholder": "New Password", "class": "width-100"}, render_value=True),)
    retype_password = forms.CharField(label="Confirm Password", widget=forms.PasswordInput(
        attrs={"placeholder": "Repeat Password", "class": "width-100"}, render_value=True))


class LoginForm(forms.Form):
    username = forms.CharField(label="Username", max_length=254, widget=forms.EmailInput(
        attrs={'placeholder': "Your email@somewhere.com"}))
    password = forms.CharField(label="Password", widget=forms.PasswordInput(
        attrs={"placeholder": "Type Password"}, render_value=True),)


class ResetForm(forms.Form):
    email = forms.CharField(label="Email", max_length=254, widget=forms.EmailInput(
        attrs={'placeholder': "Your email@somewhere.com"}))
