<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Apache Casbin C++ (Incubating): local Python bindings

Apache Casbin is an effort undergoing incubation at The Apache Software
Foundation (ASF), sponsored by the Apache Incubator. Incubation is required of
all newly accepted projects until a further review indicates that the
infrastructure, communications, and decision making process have stabilized
in a manner consistent with other successful ASF projects. While incubation
status is not necessarily a reflection of the completeness or stability of
the code, it does indicate that the project has yet to be fully endorsed by
the ASF.

Use a dedicated virtual environment for these local bindings. The historical
`pycasbin` distribution name also identifies a different, pure-Python PyPI
project; this preparation does not add a PyPI publisher.

At present, `casbin-cpp` provides language bindings for Python, we named it `pycasbin`.

## Python Bindings

### Use `pip` install the `pycasbin` module

It is assumed you have `CMake >=v3.19` and `Python >= 3.9` installed. Current `pycasbin` only support `pip` install in local machine.

1. Clone/download the project:
    ```bash
    git clone https://github.com/apache/casbin-cpp.git
    ```

2. Update `wheel setuptools`:
    ```bash
    python -m pip install --upgrade wheel setuptools
    ```
    
3. Install the `pycasbin` module:
    ```bash
    cd casbin-cpp && pip install --verbose .
    ```

Now, you're ready to go!

### Usage

It is assumed that you have `pycasbin` module correctly installed on your system.

First, we import the `pycasbin` module to a python source file:

```python
import pycasbin as casbin
```

Suppose we want a function to check authorization of a request:

```python
def isAuthorized(req):
    result = True
    if result:
        print('Authorized')
    else
        print('Not authorized!')
```

Here, the request can be a list or a dictionary in the forms:

```python
req = ['subject1', 'object1', 'action1'] # and so on..

req = {
    "sub": "subject1",
    "obj": "object1",
    "act": "action1"  # ... and so on
}
```

We can Enforce this request (or compute the `result` of this request) through `casbin.Enforce()`. 
For that, we need to create a `casbin.Enforcer`:

```python
e = casbin.Enforcer('path/to/model.conf', 'path/to/policy.csv')
```
Make sure that the paths are relative to the current python source file or an absolute path.

Apart from the regular `Enforcer`, you may also use `CachedEnforcer`
depending on your use case.

Incorporating the `Enforcer` in our example gives us:

```python
def isAuthorized(req):
    result = e.Enforce(req)
    if result:
        print('Authorized')
    else
        print('Not authorized!')
```

Rest of the method's name is on par with `casbin-cpp`.

#### Summary

This sums up the basic usage of `pycasbin` module:

```python
import pycasbin as casbin

e = casbin.Enforcer('path/to/model.conf', 'path/to/policy.csv')

def isAuthorized(req):
    result = e.Enforce(req)
    if result:
        print('Authorized')
    else
        print('Not authorized!')

isAuthorized(['subject1', 'object1', 'action1'])
isAuthorized(['subject2', 'object2', 'action2'])
# ... and so on
```

If you've done everything right, you'll see your output
without any errors.
