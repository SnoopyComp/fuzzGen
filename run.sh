#  $1: 생성할 파일 이름
#  $2: recursive count
#  $3: memory format
#!/bin/bash

if [-f .env ]; then
	export $(cat .env | xargs)
fi

export OPENAI_API_KEY=$OPENAI_API_KEY



directory_name=$1

if [ -n "$3" ]; then
	docker rm $(docker ps -qa)
	docker rmi $(docker image -q)
	docker system prune -a
	sudo rm -rf /tmp/*
	rm -rf ~/.local/share/Trash/files/*
fi

for ((var=1; var<=$2; var++));
do
	./run_all_experiments.py\
		--model='gpt-4o'\
		-y ./benchmark-sets/all/libraw.yaml\
		--work-dir=results/${directory_name}$var

	python3.11 -m report.web -r results/${directory_name}$var -o outputs/${directory_name}$var
done
