import os

from flask import jsonify, make_response, request
from flask_restx import Namespace, Resource

from database.auth_db import upsert_auth, verify_api_key
from utils.logging import get_logger

api = Namespace("inject_token", description="Inject broker auth token programmatically")

logger = get_logger(__name__)


@api.route("/", strict_slashes=False)
class InjectToken(Resource):
    def post(self):
        """Inject a broker access token without going through OAuth.

        Used when the OAuth redirect URL points to a different service (e.g.
        Nifty Quant Engine) that completes the token exchange and forwards the
        resulting access_token here so OpenAlgo can place orders without
        requiring its own separate OAuth flow.

        Request body:
            apikey       – OpenAlgo API key (identifies + authenticates the caller)
            access_token – Raw broker access token (Zerodha: the value after
                           the session exchange, before api_key: prefix)
            broker       – Broker name, default "zerodha"
        """
        try:
            data = request.json or {}
            api_key = data.get("apikey", "")
            access_token = data.get("access_token", "")
            broker = data.get("broker", "zerodha")

            if not api_key:
                return make_response(jsonify({"status": "error", "message": "apikey is required"}), 400)
            if not access_token:
                return make_response(jsonify({"status": "error", "message": "access_token is required"}), 400)

            username = verify_api_key(api_key)
            if not username:
                return make_response(jsonify({"status": "error", "message": "Invalid API key"}), 403)

            broker_api_key = os.getenv("BROKER_API_KEY", "")
            # Zerodha stores the token as "api_key:access_token"
            stored_token = f"{broker_api_key}:{access_token}" if broker == "zerodha" else access_token

            inserted = upsert_auth(username, stored_token, broker)
            if inserted:
                logger.info(f"Token injected for user={username} broker={broker} via inject_token API")
                return make_response(jsonify({"status": "success"}), 200)

            return make_response(jsonify({"status": "error", "message": "Failed to store token"}), 500)

        except Exception:
            logger.exception("Unexpected error in InjectToken endpoint")
            return make_response(jsonify({"status": "error", "message": "Internal server error"}), 500)
