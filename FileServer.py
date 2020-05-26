import socket 
import json
import sys
import pathlib
from shutil import rmtree, copy
from email.parser import Parser

MAX_LINE = 64*1024
MAX_HEADERS = 100
CONT_TYPE = {".pdf": "application/pdf",
            ".txt": "text/plain",
            ".html": "text/html",
            ".exe": "application/octet-stream",
            ".zip": "application/zip",
            ".doc": "application/msword",
            ".xls": "application/vnd.ms-excel",
            ".ppt": "application/vnd.ms-powerpoint",
            ".gif": "image/gif",
            ".png": "image/png",
            ".jpeg": "image/jpg",
            ".jpg": "image/jpg",
            ".php": "text/plain",
            ".json": "application/json",
            "default": "application/octet-stream"}

class Request:
        def __init__(self, method, target, version, headers, rfile):
            self.method = method
            self.target = target
            self.version = version
            self.headers = headers
            self.rfile = rfile

        @property
        def path(self):
            return self.target

        def body(self):
            size = self.headers.get('Content-Length')
            if not size:
                return None
                
            return self.rfile.read(int(size))

class Response:
    def __init__(self, status, reason, headers=None, body=None):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body

class HTTPError(Exception):
  def __init__(self, status, reason, body=None):
    super()
    self.status = status
    self.reason = reason
    self.body = body

class HTTPServer:

    def __init__(self, host, port, server_name):
        self._host = host
        self._port = port
        self._server_name = server_name

    def serve_forever(self):
        serv_sock = socket.socket(socket.AF_INET,
                                socket.SOCK_STREAM,
                                proto=0)

        try:
            serv_sock.bind((self._host, self._port))
            serv_sock.listen() 

            while True:
                conn, _ = serv_sock.accept()
                try:
                    self.serve_client(conn)
                except Exception as e:
                    print('Client serving failed', e)
        finally:
            serv_sock.close()

    def listenForConn(self):

        while True:
            # Establish the connection
            conn_sock, _ = self.server_socket.accept() 

            # Create new thread
            # thread = threading.Thread(target=, args=(connet, client_addr))
            thread.setDaemon(True)
            thread.start()
        self.shutdown()

    def serve_client(self, conn):
        try:
            req = self.parse_request(conn)
            resp = self.handle_request(req)
            self.send_response(conn, resp)
        except ConnectionResetError:
            conn = None
        except Exception as e:
            self.send_error(conn, e)

        if conn:
            req.rfile.close()
            conn.close()

    def parse_request(self, conn):
        rfile = conn.makefile('rb')
        method, target, ver = self.parse_request_line(rfile)
        headers = self.parse_headers(rfile)
        host = headers.get('Host')

        if not host:
            raise HTTPError(400, 'Bad request',
                b'Host header is missing')
        if host not in (self._server_name,
                        f'{self._host}:{self._port}'):
            raise HTTPError(404, 'Not found')

        return Request(method, target, ver, headers, rfile)

    def parse_request_line(self, rfile):
        raw = rfile.readline(MAX_LINE + 1)
        if len(raw) > MAX_LINE:
            raise HTTPError(400, 'Bad request',
                b'Request line is too long')

        req_line = str(raw, 'iso-8859-1')
        words = req_line.split()
        if len(words) != 3:
            raise HTTPError(400, 'Bad request',
                b'Malformed request line')

        method, target, ver = words
        if ver != 'HTTP/1.1':
            raise HTTPError(505, b'HTTP Version Not Supported')
        return method, target, ver

    def parse_headers(self, rfile):
        headers = []
        while True:
            line = rfile.readline(MAX_LINE + 1)
            if len(line) > MAX_LINE:
                raise HTTPError(400, 'Bad request',b'Header line is too long')

            if line in (b'\r\n', b'\n', b''):
                # завершаем чтение заголовков
                break

            headers.append(line)
            if len(headers) > MAX_HEADERS:
                raise HTTPError(400, 'Bad request',b'Too many headers')

        sheaders = b''.join(headers).decode('iso-8859-1')
        return Parser().parsestr(sheaders)

    def handle_request(self,request):
        if request.method == 'GET':
            return self.get_req(request)

        elif request.method == 'PUT':
            if request.headers.get('X-Copy-From'):
                return self.copy_req(request)
            else:
                return self.put_req(request)

        elif request.method == 'HEAD':
            return self.head_req(request)

        elif request.method == 'DELETE':
            return self.delete_req(request)

    def send_response(self, conn, resp):
        wfile = conn.makefile('wb')
        status_line = f'HTTP/1.1 {resp.status} {resp.reason}\r\n'
        wfile.write(status_line.encode('iso-8859-1'))

        if resp.headers:
            for (key, value) in resp.headers:
                header_line = f'{key}: {value}\r\n'
                wfile.write(header_line.encode('iso-8859-1'))

        wfile.write(b'\r\n')

        if resp.body:
            wfile.write(resp.body)

        wfile.flush()
        wfile.close()

    def send_error(self, conn, err):
        try:
            status = err.status
            reason = err.reason.encode('utf-8')
            body = (err.body or err.reason)
        except:
            status = 500
            reason = b'Internal Server Error'
            body = b'Internal Server Error'
        
        resp = Response(status, reason,
                    [('Content-Length', len(body))],
                    body)

        self.send_response(conn, resp)

    def get_req(self, request):
        path = pathlib.Path(request.path)

        if path.exists():
            if path.is_file():
                f = open(path,'rb')
                body = f.read()

                headers = [('Content-Length',len(body)),
                        ('Content-Type', CONT_TYPE.get(path.suffix)),
                        ('Content-Disposition',f'attachment; filename="newfile{path.suffix}"')]

            else:
                files = []
                folders = []
                for item in path.iterdir():
                    if item.is_file():
                        files.append(item.name)
                    else:
                        folders.append(item.name)

                to_json = {'files': files, 'folders': folders}
                body = json.dumps(to_json).encode('iso-8859-1')

                headers = [('Content-Length',len(body)),
                        ('Content-Type', CONT_TYPE.get(".json")),
                        ('Content-Disposition','inline')]

            return Response(200, 'OK', headers, body)
        else:
            body = f'Incorrect Path: {path}'.encode('iso-8859-1')
            raise HTTPError(404, 'Not found', body)


    def put_req(self, request):
        path = pathlib.Path(request.path)
        content = request.body()

        new_folder = path.parent
        if not new_folder.exists():
            new_folder.mkdir(parents=True)

        if not path.is_dir:
            try:
                f = open(path, 'wb')
                f.write(content)
                body = b'File uploaded'
            except Exception as ex:
                body = f'Exception raised during file uploading'.encode('iso-8859-1')
                raise HTTPError(500,'Internal Server Error', body)
            finally:
                f.close()
        else:
            body = b'Empty Folder Created'        
    
        return Response(201, 'Created',[('Content-Length', len(body))], body)    

    def copy_req(self, request):
        new_path = pathlib.Path(request.path)
        copy_from = pathlib.Path(request.headers.get('X-Copy-From'))

        if copy_from.exists():
            try:
                if new_path.is_dir():
                    new_folder = new_path
                else:
                    new_folder = new_path.parent

                if not new_folder.exists():
                    new_folder.mkdir(parents=True)

                copy(copy_from, new_path)
            except Exception as ex:
                raise HTTPError(406, 'Not Acceptable')
        else:
            raise HTTPError(404, 'Not Found')

        return Response(200, 'OK', [('Content-Length', len('Copied'))], b'Copied')


    def head_req(self, request):
        path = pathlib.Path(request.path)

        if path.exists():
            if path.is_file():
                headers = [('Content-Length', path.stat().st_stat),
                            ('Content-Type', CONT_TYPE.get(path.suffix)),
                            ('Content-Disposition','attachment, filename="newfile"')]

                return Response(200, 'OK',headers)
            else:
                body = b'Folder Not Found'
                return Response(404, 'Not Found', [('Content-Length', len(body))], body)
        else:
            body = f'Incorrect Path: {path}'.encode('iso-8859-1')
            raise HTTPError(404, 'Not found', body)   

    def delete_req(self, request):
        path = pathlib.Path(request.path)

        if path.exists():
            try:
                if path.is_file():
                    path.unlink()
                else:
                    rmtree(path)

                body = f'Deleted'.encode('iso-8859-1')
            except Exception as ex:
                body = f'Exception raised {ex}'.encode('iso-8859-1')
                raise HTTPError(500,'Internal Server Error', body)

            return Response(200, 'OK', [('Content-Length', len(body))], body)
        else:
            body = b'Incorrect Path'
            raise HTTPError(404, 'Not found', body)


if __name__ == "__main__":
    host = 'localhost'
    port = 12345
    name = 'FileServer'

    serv = HTTPServer(host, port, name)
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        pass