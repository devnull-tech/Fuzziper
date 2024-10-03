import json
import threading
import requests

class Fuzzer:
    def __init__(self, wordlist_path: str, threads: int = 10, read_mode: bool = False) -> None:
        self.read_mode = read_mode
        if not self.read_mode:
            with open(wordlist_path, 'r') as file:
                self.wordlist = file.readlines()
            self.threads = threads
            self.wordlist_fragments = self._fragment_wordlist()
            self.thread_list = []
        self.output = [] # {'url': 'http://ss.com/s', 'status_code': 200, 'response_len': 1956}
    
    def _fragment_wordlist(self) -> list:
        fragment_len = len(self.wordlist) // self.threads
        wordlist_fragments = []
        for i in range(self.threads):
            ini = i * fragment_len
            end =  len(self.wordlist)
            if i != self.threads - 1:
               end = (i + 1) * fragment_len
            wordlist_fragments.append(self.wordlist[ini:end])
        return wordlist_fragments

    def filter_len(self, min: int, max: int) -> list:
        if self.output == []:
            return []
        filter_len = []
        for i in self.output:
            if i['response_len'] >= min:
                if max:
                    if i['response_len'] <= max:
                        filter_len.append(i)
                else:
                    filter_len.append(i)
        return filter_len

    def filter_status(self, filter: list = [404]) -> list:
        if self.output == []:
            return []
        filtered_list = []
        for i in self.output:
            if not i['status_code'] in filter:
                filtered_list.append(i)
        return filtered_list

    def deploy_fuzz(self, url: str, method: str = 'GET') -> None:
        self.output = []
        for wordlist_fragment in self.wordlist_fragments:
            thread = threading.Thread(target=self.requests_thread, args=(wordlist_fragment, url, method))
            self.thread_list.append(thread)
            thread.start()
        for thread in self.thread_list:
            thread.join()

    def requests_thread(self, wordlist_segment: list, base_url: str, method: str = 'GET') -> None:
        for word in wordlist_segment:
            url = base_url
            if url[len(url)-1] != "/":
                url += "/"
            url += word.rstrip('\n')
            try:
                response = None
                if method == 'HEAD':
                    response = requests.head(url)
                if method == 'GET':
                    response = requests.get(url)
                self.output.append({
                    'url': url,
                    'status_code': response.status_code,
                    'response_len': len(response.content)
                })
            except Exception:
                pass

    def export_output(self, name: str = "output.txt") -> None:
        with open(name, 'w') as archivo_json:
            json.dump(self.output, archivo_json, indent=4)
    
    def input_from_file(self, path: str) -> None:
        try:
            with open(path, 'r') as file:
                data = json.load(file)
            self.output = data
        except FileNotFoundError:
            print(f"The {path} file was not found.")
        except json.JSONDecodeError:
            print(f"Error decoding {path} file.")
        except Exception as e:
            print(f"An error occurred: {e}")
    
    @staticmethod
    def get_printable(responses: list) -> str:
        index = responses[0]['url'].rfind('/')
        base_url = responses[0]['url'][:index + 1]
        returnable = "Fuzziper output for " + base_url
        for i in responses:
            returnable += "\n" + "/" + i['url'].split("/")[-1] + " -> ["+str(i['status_code'])+"] --- length: " + str(i['response_len'])
        return returnable