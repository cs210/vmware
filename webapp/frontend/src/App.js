import React, { Component } from 'react';
import './App.css';
import Form from 'react-bootstrap/Form';
import Col from 'react-bootstrap/Col';
import Container from 'react-bootstrap/Container';
import Row from 'react-bootstrap/Row';
import Button from 'react-bootstrap/Button';
import 'bootstrap/dist/css/bootstrap.css';

class App extends Component {

  constructor(props) {
    super(props);

    // Global React state
    this.state = {
      isLoading: false,
      formData: {
        textfield: '',
      },
      result: ""
    };
  }

  handleChange = (event) => {
    const value = event.target.value;
    const name = event.target.name;
    var formData = this.state.formData;
    formData[name] = value;
    this.setState({
      formData
    });
  }

  handleCancelClick = (event) => {
    this.setState({ result: "" });
  }

  handleAnalysisClick = (event) => {
    event.preventDefault();
    const data = new FormData();
    data.append('file', this.uploadInput);
    this.setState({ isLoading: true });

    fetch('http://127.0.0.1:5000/static_telemetry/', {
      method: 'POST',
      body: data,
    })
    .then(response => response.json())
    .then((response) => {
      // TODO: Style response.output
      this.setState({
        result: response.output,
        isLoading: false
      });
    });
  }

  render() {
    const isLoading = this.state.isLoading;
    const formData = this.state.formData;
    const result = this.state.result;

    return (
      <Container>
        {/* Title */}
        <div>
          <h1 className="title">VirusTotal++</h1>
        </div>
        
        {/* Main body */}
        <div className="content">
          <Form>
            <Form.Row>
              <Form.Group as={Col}>
                <Form.Label>Upload a portable executable (PE) file</Form.Label>
                {/* File upload */}
                <Form.Control 
                  type="file" 
                  placeholder="File Input" 
                  name="fileinput"
                  value={formData.textfield1}
                  onChange={(e) => this.uploadInput = e.target.files[0]} 
                />
              </Form.Group>
              { /* TODO: For additional options
              <Form.Group as={Col}>
                <Form.Label>Text Field</Form.Label>
                <Form.Control 
                  type="text" 
                  placeholder="Text Field" 
                  name="textfield"
                  value={formData.textfield}
                  onChange={this.handleChange} />
              </Form.Group>
              */}
            </Form.Row>
            <Row>
              {/* Analyze button */}
              <Col>
                <Button
                  block
                  variant="success"
                  disabled={isLoading}
                  onClick={!isLoading ? this.handleAnalysisClick : null}>
                  { isLoading ? 'Analyzing' : 'Analyze' }
                </Button>
              </Col>
              {/* Cancel button */}
              <Col>
                <Button
                  block
                  variant="danger"
                  disabled={isLoading}
                  onClick={this.handleCancelClick}>
                  Reset analysis
                </Button>
              </Col>
            </Row>
          </Form>

          {/* Display result */}
          {result === "" ? null :
            (<Row>
              <Col className="result-container">
                <h5 id="result">{result}</h5>
              </Col>
            </Row>)
          }
        </div>
      </Container>
    );
  }
}

export default App;