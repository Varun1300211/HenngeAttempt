import requests
import base64

def generate_totp_password(user_id, shared_secret):
  """Generates a time-based one-time password (TOTP) password.

  Args:
    user_id: The user ID.
    shared_secret: The shared secret.

  Returns:
    A TOTP password.
  """

  import hmac
  import hashlib

  epoch = time.time()
  time_step = 30
  t0 = 0

  counter = (epoch - t0) // time_step

  digest = hmac.digest(shared_secret.encode(), counter.to_bytes(8, 'big'), hashlib.sha512)
  truncated_digest = digest[0:6]
  offset = truncated_digest[0] & 0x0f

  password = (truncated_digest[offset:offset + 4]) // 0x100000 % 1000000

  return str(password).zfill(6)

def send_http_post_request(user_id, json_string):
  """Sends an HTTP POST request with the JSON string as the body part.

  Args:
    user_id: The user ID.
    json_string: The JSON string.

  Returns:
    A response object.
  """

  session = requests.Session()

  headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Basic ' + base64.b64encode(requests.auth.HTTPBasicAuth(user_id, user_id + 'HENNGECHALLENGE003').encode('utf-8')).decode('utf-8'),
    'TOTP': generate_totp_password(user_id, user_id + 'HENNGECHALLENGE003')
  }

  request = requests.Request('POST', 'https://api.challenge.hennge.com/challenges/003', headers=headers, data=json_string)

  response = session.send(request)

  return response

if __name__ == '__main__':
  user_id = 'varunkumarg246@gmail.com'
  json_string = """{
    "github_url": "https://gist.github.com/Varun1300211/8295642b4fef870b51fab974d5ba4f6d",
    "contact_email": "varunkumarg246@gmail.com",
    "solution_language": "python"
  }"""

  response = send_http_post_request(user_id, json_string)

  if response.status_code == 200:
    print('Request succeeded!')
  else:
    print('Request failed: {}'.format(response.status_code))
