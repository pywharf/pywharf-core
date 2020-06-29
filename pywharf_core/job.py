import os
import functools


class DynamicDramatiq:

    def __init__(self) -> None:
        self.broker = None
        self.func_to_actor_kwargs = {}
        self.func_to_actor = {}

    def actor(self, **actor_kwargs):

        def decorator(func):
            self.func_to_actor_kwargs[func] = actor_kwargs

            @functools.wraps(func)
            def wrapped(*args, **kwargs):
                actor = self.func_to_actor.get(func)
                if actor is None:
                    raise RuntimeError('Broker not set.')

                return actor.send(*args, **kwargs)

            return wrapped

        return decorator

    def set_broker(self, broker):
        import dramatiq

        self.broker = broker
        dramatiq.set_broker(broker)

        self.func_to_actor = {}
        for func, actor_kwargs in self.func_to_actor_kwargs.items():
            self.func_to_actor[func] = dramatiq.actor(**actor_kwargs)(func)


dynamic_dramatiq = DynamicDramatiq()

# If set, enter worker mode.
_REDIS_BROKER_PORT = os.getenv('DYNAMIC_DRAMATIQ_REDIS_BROKER_PORT')
if _REDIS_BROKER_PORT:
    # 1. Load actors.
    import pywharf_core.workflow  # noqa: F401
    from pywharf_core.backend import BackendInstanceManager
    BackendInstanceManager()

    # 2. Connect to broker.
    from dramatiq.brokers.redis import RedisBroker
    REDIS_BROKER = RedisBroker(host='localhost', port=_REDIS_BROKER_PORT)
    dynamic_dramatiq.set_broker(REDIS_BROKER)
