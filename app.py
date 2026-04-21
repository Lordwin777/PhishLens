from flask import Flask, request, jsonify, render_template
from checker.url_check import scan

app = Flask(__name__,
            template_folder='website/body',
            static_folder='website/body',
            static_url_path='')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_url():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        if not url:
            return jsonify({'error': 'Please enter a URL'}), 400
        if not url.startswith('http'):
            url = 'http://' + url
        result = scan(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)