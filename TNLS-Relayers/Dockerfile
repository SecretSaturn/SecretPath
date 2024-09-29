# Use an official Python 3.11 runtime
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the dependencies specified in requirements.txt
RUN pip install --no-dependencies -r requirements.txt

# Copy the rest of your application code into the container
COPY . .

# Expose the port your app runs on
EXPOSE 8000

# Command to the relayer
CMD ["python3", "web_app.py"]