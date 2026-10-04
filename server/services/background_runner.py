"""Single background owner; never run beside the combined scheduler."""
import os
from services.process_role import role
from services.lifecycle import stopping, install_signal_handlers, wait_for_workers


def main():
    os.environ['WARDEN_PROCESS_ROLE'] = 'background'
    if role() != 'background':
        raise RuntimeError('Invalid background role')
    install_signal_handlers()
    # app import initializes the background services in the worker process.
    import app
    try:
        stopping.wait()
    finally:
        wait_for_workers()


if __name__ == '__main__':
    main()
