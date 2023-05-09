# Specify the Dart SDK base image version using dart:<version> (ex: dart:2.12)          2.19 as of Feb 2023
FROM dart:2.19 AS build         

#Prep files and dirs
COPY . /app
RUN mkdir -p /app/dart/bin

#Install dependecies and compile minimal serving image from AOT-compiled and required system
WORKDIR /app/dart/src
RUN dart pub get
# RUN dart compile exe run-prover.dart -o /app/bin/run-prover
# RUN dart compile exe run-challenger.dart -o /app/bin/run-challenger

WORKDIR /app/dart/run
RUN ./build

# libraries and configuration files stored in `/runtime/` from the build stage.
FROM scratch AS pob_prover
COPY --from=build /runtime/ /
COPY --from=build /app/dart/bin/pob/run-pob-prover.exe /app/bin/pob/run-pob-prover.exe
COPY ./config/pob    /app/bin/pob/config/
# Start server.
WORKDIR /app/bin/pob
EXPOSE 8080
CMD ["./run-pob-prover.exe"]

# libraries and configuration files stored in `/runtime/` from the build stage.
FROM scratch AS pob_challenger
COPY --from=build /runtime/ /
COPY --from=build /app/dart/bin/pob/run-pob-challenger.exe /app/bin/pob/run-pob-challenger.exe
COPY ./config/pob    /app/bin/pob/config/
# Start server.
WORKDIR /app/bin/pob
EXPOSE 8080
CMD ["./run-pob-challenger.exe"]

FROM scratch AS pol_prover
COPY --from=build /runtime/ /
COPY --from=build /app/dart/bin/pol/run-pol-prover.exe /app/bin/pol/run-pol-prover.exe
COPY ./config/pol    /app/bin/pol/config/
# Start server.
WORKDIR /app/bin/pol
EXPOSE 8080
CMD ["./run-pol-prover.exe"]

# libraries and configuration files stored in `/runtime/` from the build stage.
FROM scratch AS pol_challenger
COPY --from=build /runtime/ /
COPY --from=build /app/dart/bin/pol/run-pol-challenger.exe /app/bin/pol/run-pol-challenger.exe
COPY ./config/pol    /app/bin/pol/config/
# Start server.
WORKDIR /app/bin/pol
EXPOSE 8080
CMD ["./run-pol-challenger.exe"]

