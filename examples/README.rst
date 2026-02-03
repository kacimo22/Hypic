Examples
========

After checking out the code using git you can run:

.. code-block:: console

   pip install . dnslib jinja2 starlette wsproto


HTTP/3
------

HTTP/3 server
.............

You can run the example server as follows:

.. code-block:: console

cd Hypic

Then

.. code-block:: console

python3 examples/http3_server.py --catalyst-config server_config.json

HTTP/3 lgacy client
.............

You can run the legacy client to perform an HTTP/3 request:

.. code-block:: console

  python3 examples/http3_client.py --insecure https://localhost:4433/


HTTP/3 PQ-aware client
.............

You can run the PQ-aware client to perform PQ Initial Handshake (PQIH):

.. code-block:: console

  python3 examples/http3_client.py --insecure  https://localhost:4433/ --enable-pq  kyber768 --max-rpqh-period 3600

You can also run the PQ-aware client to perform PQ Resumed Handshake (PQRH):

.. code-block:: console

  python3 examples/http3_client.py --insecure  https://localhost:4433/ --enable-pq  kyber768 --max-rpqh-period 3600 --session-ticket

