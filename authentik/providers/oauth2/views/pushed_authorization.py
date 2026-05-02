"""Pushed Authorization Request (PAR) endpoint"""

from django.http import Http404, HttpRequest, HttpResponse
from django.utils.decorators import method_decorator
from django.utils.timezone import now
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework.throttling import AnonRateThrottle
from structlog.stdlib import get_logger

from authentik.core.models import Application
from authentik.lib.config import CONFIG
from authentik.lib.utils.time import timedelta_from_string
from authentik.lib.views import bad_request_message
from authentik.policies.views import RequestValidationError
from authentik.providers.oauth2.errors import (
    AuthorizeError,
    OAuth2Error,
    PushedAuthorizationRequestError,
)
from authentik.providers.oauth2.models import OAuth2Provider, PushedAuthorizationData
from authentik.providers.oauth2.utils import TokenResponse, authenticate_provider
from authentik.providers.oauth2.views.authorize import OAuthAuthorizationParams

LOGGER = get_logger()


@method_decorator(csrf_exempt, name="dispatch")
class PushedAuthorizationView(View):
    """
    Pushed Authorization Request flow, clients can push authorization data
    ahead of browser redirect
    """

    provider: OAuth2Provider

    def parse_request(self):
        """Parse incoming request"""
        provider = authenticate_provider(self.request)
        if not provider:
            raise PushedAuthorizationRequestError("unauthorized_client")
        try:
            _ = provider.application
        except Application.DoesNotExist:
            raise PushedAuthorizationRequestError("unauthorized_client") from None
        self.provider = provider

    def post(self, request: HttpRequest) -> HttpResponse:
        """Register authorize data via backchannel API"""
        try:
            self.parse_request()
        except PushedAuthorizationRequestError as exc:
            return TokenResponse(exc.create_dict(request), status=400)

        if not self.provider.client_secret:
            throttle = AnonRateThrottle()
            throttle.rate = CONFIG.get("throttle.providers.oauth2.par_non_confidential", "20/hour")
            throttle.num_requests, throttle.duration = throttle.parse_rate(throttle.rate)
            if not throttle.allow_request(request, self):
                return TokenResponse(
                    PushedAuthorizationRequestError("slow_down").create_dict(request), status=429
                )

        # when we create PAR data don't allow recursive usage of PAR (i.e. request_uri).
        try:
            data = OAuthAuthorizationParams.from_request(request, is_pushed_authorization=True)
        except AuthorizeError as error:
            LOGGER.warning(error.description, redirect_uri=error.redirect_uri, cause=error.cause)
            raise RequestValidationError(error.get_response(self.request)) from None
        except OAuth2Error as error:
            LOGGER.warning(error.description, cause=error.cause)
            raise RequestValidationError(
                bad_request_message(self.request, error.description, title=error.error)
            ) from None
        except OAuth2Provider.DoesNotExist:
            raise Http404 from None

        until = timedelta_from_string(self.provider.access_code_validity)

        par_data: PushedAuthorizationData = PushedAuthorizationData.objects.create(
            expires=now() + until, data=data
        )
        return TokenResponse(
            {
                "request_uri": par_data.request_uri,
                "expire_in": int(until.total_seconds()),
            }
        )
