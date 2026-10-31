# One image, five apps: each container app runs a different entry point with its own identity.
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY . .
RUN for p in Api Writer Webhook FakeMews SuggestionWorker; do \
      dotnet publish src/RateDemo.$p/RateDemo.$p.csproj -c Release -o /app/$p --nologo; \
    done

FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app /app
ENV ASPNETCORE_HTTP_PORTS=8080
USER $APP_UID
