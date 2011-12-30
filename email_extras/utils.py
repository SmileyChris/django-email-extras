
from __future__ import with_statement
from os.path import basename

from django.template import loader, Context, TemplateDoesNotExist
from django.core import mail

from email_extras.settings import USE_GNUPG, GNUPG_HOME


if USE_GNUPG:
    from gnupg import GPG
    from email_extras.models import Address


def addresses_for_key(gpg, key):
    """
    Takes a key and extracts the email addresses for it.
    """
    fingerprint = key["fingerprint"]
    addresses = []
    for key in gpg.list_keys():
        if key["fingerprint"] == fingerprint:
            addresses.extend([address.split("<")[-1].strip(">")
                              for address in key["uids"] if address])
    return addresses


def send_mail(subject, message, from_email, recipient_list,
              fail_silently=False, auth_user=None, auth_password=None,
              connection=None, attachments=None, html_message=None):
    """
    Sends a multipart email containing text and html versions which are
    encrypted for each recipient that has a valid gpg key installed.
    """
    # Allow for a single address to be passed in.
    if isinstance(recipient_list, basestring):
        recipient_list = [recipient_list]

    # Obtain a list of the recipients that have gpg keys installed.
    valid_key_addresses = []
    if USE_GNUPG:
        queryset = Address.objects.filter(address__in=recipient_list)
        valid_key_addresses = queryset.values_list("address", flat=True)
        # Create the gpg object.
        if valid_key_addresses:
            gpg = GPG(gnupghome=GNUPG_HOME)

    def encrypt_if_key(body, addr):
        """
        Encrypts body if recipient has a gpg key installed.
        """
        if USE_GNUPG and addr in valid_key_addresses:
            return unicode(gpg.encrypt(body, addr))
        return body

    # Load attachments and create name/data tuples.
    attachments_parts = []
    if attachments:
        for attachment in attachments:
            with open(attachment, "rb") as f:
                attachments_parts.append((basename(attachment), f.read()))

    connection = connection or mail.get_connection(username=auth_user,
        password=auth_password, fail_silently=fail_silently)
    if attachments_parts or html_message:
        message_class = mail.EmailMultiAlternatives
    else:
        message_class = mail.EmailMessage

    # Send emails.
    for addr in recipient_list:
        msg = message_class(subject, encrypt_if_key(message, addr), from_email,
            [addr], connection=connection)
        if html_message:
            msg.attach_alternative(encrypt_if_key(html_message, addr),
                "text/html")
        for parts in attachments_parts:
            msg.attach(parts[0], encrypt_if_key(parts[1], addr))
        msg.send()


def send_mail_template(subject, template, context=None, *args, **kwargs):
    """
    Send email rendering text and html versions for the specified
    template name using the context dictionary passed in.
    """
    if context is None:
        context = {}
    if not isinstance(context, Context):
        context = Context(context)

    def render(ext, required=True):
        """
        Loads (and renders) a template.
        """
        name = "%s.%s" % (template, ext)
        try:
            # The template doesn't have to belong in 'email_extras', but try
            # there first.
            tmpl = loader.select_template([
                "email_extras/%s" % name,
                name,
            ])
        except TemplateDoesNotExist:
            if required:
                raise
            return

        return tmpl.render(context)

    send_mail(subject=subject, message=render("txt"),
        html_message=render("html", required=False), *args, **kwargs)
