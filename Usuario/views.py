from django.shortcuts import render

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password, check_password

from .serializers import UserSerializer

from jwt.contrib.algorithms.pycrypto import RSAAlgorithm

import requests
import random
import os
import jwt


class LoginView(APIView):

    permission_classes = [AllowAny]

    def get(self, request):
        if not 'email' in request.query_params or not 'password' in request.query_params:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        if not User.objects.filter(email = request.query_params['email']).exists():
            return Response({"detail":"Usuario o contraseña no coinciden"}, status=status.HTTP_400_BAD_REQUEST)
        MyUser = User.objects.get(email = request.query_params['email'])
        if check_password(request.query_params['password'], MyUser.password):
            user = MyUser
            response = {
                "id":user.username,
                "nombres":user.first_name,
                "apellidos":user.last_name,
                "administrador":user.is_superuser
            }            
            return Response(response, status=status.HTTP_200_OK)
        else:
            return Response({"detail":"Usuario o contraseña no coinciden"}, status=status.HTTP_400_BAD_REQUEST)        
        return Response(status=status.HTTP_200_OK)


class UserView(APIView):

    permission_classes = [AllowAny]

    def get(self, request, id_user):
        if os.environ['REVISAR_JWT'] =='True':
            try:
                authorizationHeader = request.META.get('HTTP_AUTHORIZATION')
                token = authorizationHeader.split()            
                f = open(os.environ['PUBLIC_JWT'], "r")
                public_key = f.read()
                jwt.unregister_algorithm('RS256')
                jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))
                data = jwt.decode(token[1], public_key, audience='2' ,algorithm='RS256')
                valid = False            
                for scope in data['scopes']:
                    if scope == "usuarios.jugadores.get":
                        valid = True
                if not valid:
                    print("Token invalido")
                    return Response(status=status.HTTP_401_UNAUTHORIZED)
                print("Token Valido")
            except:
                return Response(status=status.HTTP_401_UNAUTHORIZED)
        if not User.objects.filter(username = id_user).exists():
            return Response({"detail":"Usuario no encontrado"}, status=status.HTTP_404_NOT_FOUND)
        user = User.objects.get(username = id_user)
        response = {
            "id":user.username,
            "nombres":user.first_name,
            "apellidos":user.last_name,
            "administrador":user.is_superuser
        }            
        return Response(response, status=status.HTTP_200_OK)

    def put(self, request, id_user):
        if os.environ['REVISAR_JWT'] =='True':
            try:
                authorizationHeader = request.META.get('HTTP_AUTHORIZATION')
                token = authorizationHeader.split()            
                f = open(os.environ['PUBLIC_JWT'], "r")
                public_key = f.read()
                jwt.unregister_algorithm('RS256')
                jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))
                data = jwt.decode(token[1], public_key, audience='2' ,algorithm='RS256')
                valid = False            
                for scope in data['scopes']:
                    if scope == "torneos.partida.put":
                        valid = True
                if not valid:
                    print("Token invalido")
                    return Response(status=status.HTTP_401_UNAUTHORIZED)
                print("Token Valido")
            except:
                return Response(status=status.HTTP_401_UNAUTHORIZED)
        if not User.objects.filter(username = id_user).exists():
            return Response({"detail":"Usuario no encontrado"}, status=status.HTTP_404_NOT_FOUND)
        if id_user != int(request.data['id']) and User.objects.filter(username = request.data['id']).exists():
            return Response({"detail":"Datos inválidos"}, status=status.HTTP_406_NOT_ACCEPTABLE)
        user = User.objects.get(username = id_user)
        user.username= request.data['id']
        user.first_name = request.data['nombres']
        user.last_name = request.data['apellidos']
        user.is_superuser = request.data['administrador']
        user.password = make_password(request.data['password'])
        user.save()
        response = {
            "id":user.username,
            "nombres":user.first_name,
            "apellidos":user.last_name,
            "administrador":user.is_superuser
        }
        return Response(response, status=status.HTTP_201_CREATED)
    
class CreateUserView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):
        if os.environ['REVISAR_JWT'] =='True':
            try:
                authorizationHeader = request.META.get('HTTP_AUTHORIZATION')
                token = authorizationHeader.split()            
                f = open(os.environ['PUBLIC_JWT'], "r")
                public_key = f.read()
                jwt.unregister_algorithm('RS256')
                jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))
                data = jwt.decode(token[1], public_key, audience='2' ,algorithm='RS256')
                valid = False            
                for scope in data['scopes']:
                    if scope == "torneos.partida.post":
                        valid = True
                if not valid:
                    print("Token invalido")
                    return Response(status=status.HTTP_401_UNAUTHORIZED)
                print("Token Valido")
            except:
                return Response(status=status.HTTP_401_UNAUTHORIZED)
        if not 'id' in request.data or not 'nombres' in request.data or not 'apellidos' in request.data or not 'administrador' in request.data:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        if User.objects.filter(username = request.data['id']).exists():
            return Response({"detail":"Datos inválidos"}, status=status.HTTP_406_NOT_ACCEPTABLE)
        user = User.objects.create(
            username = request.data['id'], 
            first_name=request.data['nombres'],
            last_name=request.data['apellidos'],
            is_superuser=request.data['administrador'],
            email=request.data['email'],
            password=make_password(request.data['password'])
            )
        response = {
            "id":user.username,
            "nombres":user.first_name,
            "apellidos":user.last_name,
            "administrador":user.is_superuser
        }
        return Response(response, status=status.HTTP_201_CREATED)

    def get(self, request):
        if os.environ['REVISAR_JWT'] =='True':
            try:
                authorizationHeader = request.META.get('HTTP_AUTHORIZATION')
                token = authorizationHeader.split()            
                f = open(os.environ['PUBLIC_JWT'], "r")
                public_key = f.read()
                jwt.unregister_algorithm('RS256')
                jwt.register_algorithm('RS256', RSAAlgorithm(RSAAlgorithm.SHA256))
                data = jwt.decode(token[1], public_key, audience='2' ,algorithm='RS256')
                valid = False            
                for scope in data['scopes']:
                    if scope == "torneos.partida.get":
                        valid = True
                if not valid:
                    print("Token invalido")
                    return Response(status=status.HTTP_401_UNAUTHORIZED)
                print("Token Valido")
            except:
                return Response(status=status.HTTP_401_UNAUTHORIZED)
        user = User.objects.all()
        serializer = UserSerializer(user, many=True, context={'request': request})
        response = {
            "usuarios":serializer.data
        }
        return Response(response, status=status.HTTP_200_OK)