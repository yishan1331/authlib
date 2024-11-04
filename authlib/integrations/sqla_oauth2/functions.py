import time, json
from authlib.oauth2.rfc6750 import BearerTokenGenerator
from authlib.oauth2.rfc6749 import InvalidClientError
from authlib.oauth2.rfc6749 import MaxNumOfSubAccountException


def create_query_client_func(session, client_model):
    """Create an ``query_client`` function that can be used in authorization
    server.

    :param session: SQLAlchemy session
    :param client_model: Client model class
    """
    def query_client(client_id):
        q = session.query(client_model)
        return q.filter_by(client_id=client_id).first()
    return query_client


def create_save_token_func(session, token_model, client_model=None, Yishan_dbRedis=None):
    """Create an ``save_token`` function that can be used in authorization
    server.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    :param client_model: Client model class (Yishan add)
    :param Yishan_dbRedis: redis session (Yishan add)
    """
    def save_token(token, request):
        user_id = None
        if request.user:
            user_id = request.user.get_user_id()
        client = request.client
        if user_id is None:
            user_id = client.user_id
        item = token_model(
            client_id=client.client_id,
            user_id=user_id,
            **token
        )

        #Yishan add check sub_account_counts number
        q = session.query(client_model).join(client_model.oauth2_user)\
            .filter(client_model.client_id == client.client_id,\
                client_model.client_secret == client.client_secret).first()
        num_sub_account = q.oauth2_user.num_sub_account
        if q.sub_account_counts == num_sub_account:
            raise MaxNumOfSubAccountException()

        session.add(item)
        #Yishan add update sub_account_counts +1
        q.sub_account_counts += 1

        session.commit()

        redis_value = {
            "client_id": client.client_id,
            "user_id": client.user_id,
            "scope": token.get('scope', None),
            "client_id_issued_at": client.client_id_issued_at,
            "client_secret_expires_at": client.client_secret_expires_at,
            "revoked": 0
        }
        redis_value.update(token)
        #Yishan set token in Redis 
        import json
        Yishan_dbRedis.setex(token["access_token"], BearerTokenGenerator.GRANT_TYPES_EXPIRES_IN.get("client_credentials"), json.dumps(redis_value))

    return save_token


def create_query_token_func(session, token_model):
    """Create an ``query_token`` function for revocation, introspection
    token endpoints.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    """
    def query_token(token, token_type_hint):
        q = session.query(token_model)
        if token_type_hint == 'access_token':
            return q.filter_by(access_token=token).first()
        elif token_type_hint == 'refresh_token':
            return q.filter_by(refresh_token=token).first()
        # without token_type_hint
        item = q.filter_by(access_token=token).first()
        if item:
            return item
        return q.filter_by(refresh_token=token).first()
    return query_token


def create_revocation_endpoint(session, token_model, Yishan_dbRedis):
    """Create a revocation endpoint class with SQLAlchemy session
    and token model.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    :param Yishan_dbRedis: redis session (Yishan add)
    """
    from authlib.oauth2.rfc7009 import RevocationEndpoint
    query_token = create_query_token_func(session, token_model)

    class _RevocationEndpoint(RevocationEndpoint):
        def query_token(self, token, token_type_hint):
            return query_token(token, token_type_hint)

        def revoke_token(self, token, request):
            #mysql
            now = int(time.time())
            hint = request.form.get('token_type_hint')
            token.access_token_revoked_at = now
            if hint != 'access_token':
                token.refresh_token_revoked_at = now
            session.add(token)
            session.commit()
            #===========Yishan add===========
            #redis
            #MSG: update redis token key's value:revoked
            if Yishan_dbRedis.exists(token.access_token):
                redis_value = json.loads(Yishan_dbRedis.get(token.access_token))
                redis_value["revoked"] = 1
                Yishan_dbRedis.setex(token.access_token, Yishan_dbRedis.ttl(token.access_token), json.dumps(redis_value))
            #================================

    return _RevocationEndpoint


def create_bearer_token_validator(session, token_model, client_model, Yishan_dbRedis):
    """Create an bearer token validator class with SQLAlchemy session
    and token model.

    :param session: SQLAlchemy session
    :param token_model: Token model class
    :param client_model: Client model class (Yishan add)
    :param Yishan_dbRedis: redis session (Yishan add)
    """
    from authlib.oauth2.rfc6750 import BearerTokenValidator

    class _BearerTokenValidator(BearerTokenValidator):
        def authenticate_token(self, token_string):
            #===========Yishan add===========
            return self._token_from_redis(token_string)
            #================================
            # q = session.query(token_model)
            # return q.filter_by(access_token=token_string).first()

        #===========Yishan add===========
        def _token_from_redis(self, token_string):
            if Yishan_dbRedis.exists(token_string):
                this_token = json.loads(Yishan_dbRedis.get(token_string))
                #Yishan add token existed need to check client secret is legal
                if this_token["client_id_issued_at"]+this_token["client_secret_expires_at"] < time.time():
                    self._client_token_expired(this_token["user_id"], token_string)
                    raise InvalidClientError(state=None, status_code=400)
                return json.loads(Yishan_dbRedis.get(token_string))

            #Yishan add update sub_account_counts -1
            user_id = session.query(token_model.user_id).filter_by(access_token=token_string).first()
            if user_id: self._client_token_expired(user_id[0], token_string)
            return False
        
        def _client_token_expired(self, user_id, token_string):
            session.query(client_model).filter(client_model.user_id == user_id).update({client_model.sub_account_counts : client_model.sub_account_counts - 1})
            session.query(token_model).filter_by(access_token=token_string).delete()
            session.commit()
            if Yishan_dbRedis.exists(token_string): Yishan_dbRedis.delete(token_string)
        #================================

    return _BearerTokenValidator
